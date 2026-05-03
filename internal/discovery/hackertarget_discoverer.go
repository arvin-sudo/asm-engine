package discovery

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// hackertargetBase is the root URL of the HackerTarget host search API.
//
// HackerTarget aggregates passive DNS data and exposes a free, unauthenticated
// endpoint that returns every subdomain it has observed for a given domain.
// Unlike Certificate Transparency logs — which only surface hosts that have
// had TLS certificates — HackerTarget also captures subdomains that serve
// plain HTTP or are only reachable from internal networks, widening the recon
// surface beyond what crt.sh alone can find.
const hackertargetBase = "https://api.hackertarget.com/hostsearch/"

// hackertargetSource is the source tag written into every Subdomain found by
// HackerTargetDiscoverer. It feeds into Subdomain.Source so the benchmarking
// phase can compare per-source coverage across discovery techniques.
const hackertargetSource = "hackertarget"

// HackerTargetDiscoverer implements SubdomainDiscoverer by querying the
// HackerTarget host search API.
//
// The free tier imposes a daily request quota. When the quota is exceeded,
// HackerTarget returns HTTP 429. Rather than treating that as a fatal error
// and aborting the pipeline, Discover returns an empty result so that other
// sources in a MultiSourceDiscoverer can still contribute findings.
type HackerTargetDiscoverer struct {
	client HTTPClient
}

// NewHackerTargetDiscoverer constructs a HackerTargetDiscoverer backed by the
// provided HTTP client. The caller must configure a non-zero Timeout on the
// client — an unlimited client hangs indefinitely if HackerTarget is slow.
func NewHackerTargetDiscoverer(client HTTPClient) *HackerTargetDiscoverer {
	return &HackerTargetDiscoverer{client: client}
}

// Discover queries HackerTarget for all known subdomains of domain.
//
// A 429 response is treated as an empty result rather than an error — the free
// tier quota being exhausted is a transient infrastructure limit, not a fault
// in the pipeline. All other non-200 responses are returned as errors.
func (d *HackerTargetDiscoverer) Discover(domain string) ([]models.Subdomain, error) {
	endpoint := hackertargetBase + "?q=" + url.QueryEscape(domain)

	resp, err := d.client.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("hackertarget_discoverer: request failed: %w", err)
	}
	defer resp.Body.Close()

	// 429 means the free-tier daily quota is exhausted. Return an empty slice
	// so the pipeline continues with whatever other sources produce.
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackertarget_discoverer: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("hackertarget_discoverer: read body: %w", err)
	}

	return parseHackerTargetLines(string(body), domain, hackertargetSource), nil
}

// parseHackerTargetLines converts the plain-text HackerTarget response into a
// deduplicated slice of Subdomain values scoped to targetDomain.
//
// The response format is one entry per line: "hostname,ip". Lines without a
// comma are silently skipped — this handles both malformed entries and the
// "API count exceeded" error string that some HackerTarget configurations
// embed in a 200 response body alongside the normal data.
//
// Scope filtering mirrors parseSubdomains in ct_discoverer.go: only names that
// equal or are direct subdomains of targetDomain are kept, preventing unrelated
// domains from leaking into the scan results.
func parseHackerTargetLines(body, targetDomain, source string) []models.Subdomain {
	target := strings.ToLower(strings.TrimSpace(targetDomain))
	seen := make(map[string]struct{})
	var result []models.Subdomain

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ",") {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(strings.SplitN(line, ",", 2)[0]))
		if name == "" {
			continue
		}
		if name != target && !strings.HasSuffix(name, "."+target) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, models.Subdomain{Name: name, Source: source})
	}
	return result
}
