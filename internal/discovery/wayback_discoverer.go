package discovery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// waybackBase is the root URL of the Wayback Machine CDX API.
//
// The CDX (Capture DeX) API indexes every URL the Wayback Machine has ever
// archived. Querying "*.domain" returns historical hostnames that appeared in
// archived links, form targets, and resource paths — including subdomains that
// no longer have active TLS certificates and are therefore invisible to CT
// log searches. This makes it a complementary source for finding forgotten or
// decommissioned assets that may still have live DNS records.
const waybackBase = "https://web.archive.org/cdx/search/cdx"

// waybackSource is the source tag written into every Subdomain found by
// WayBackDiscoverer.
const waybackSource = "wayback"

// WayBackDiscoverer implements SubdomainDiscoverer by querying the Wayback
// Machine CDX API for historical URLs associated with the target domain.
//
// Hostnames are extracted from the URL field of each archived record and
// filtered to the target domain scope. The result set is bounded by a
// per-request limit to keep CLI latency predictable.
type WayBackDiscoverer struct {
	client HTTPClient
}

// NewWayBackDiscoverer constructs a WayBackDiscoverer backed by the provided
// HTTP client. Set a Timeout of at least 30 seconds — the CDX API can be slow
// for popular domains with large archive histories.
func NewWayBackDiscoverer(client HTTPClient) *WayBackDiscoverer {
	return &WayBackDiscoverer{client: client}
}

// Discover queries the Wayback Machine CDX API for all archived URLs under
// domain, extracts unique hostnames, and returns them scoped to domain.
//
// The CDX API returns a JSON array of string arrays. The first element is a
// header row (["original"]); each subsequent element is a one-field array
// holding an archived URL. Hostnames are parsed from each URL using net/url
// so that ports, paths, and query strings are stripped correctly.
func (d *WayBackDiscoverer) Discover(domain string) ([]models.Subdomain, error) {
	// url=*.domain captures all subdomains ever archived.
	// fl=original restricts the response to just the URL field, minimising
	// response size. collapse=urlkey deduplicates by URL key before the
	// response leaves the CDX server. limit=10000 caps the result set so that
	// domains with enormous archive histories don't stall the CLI.
	params := url.Values{}
	params.Set("url", "*."+domain)
	params.Set("output", "json")
	params.Set("fl", "original")
	params.Set("collapse", "urlkey")
	params.Set("limit", "10000")
	endpoint := waybackBase + "?" + params.Encode()

	resp, err := d.client.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("wayback_discoverer: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback_discoverer: unexpected status %d", resp.StatusCode)
	}

	var records [][]string
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, fmt.Errorf("wayback_discoverer: json decode: %w", err)
	}

	return parseWayBackRecords(records, domain, waybackSource), nil
}

// parseWayBackRecords extracts unique in-scope hostnames from the CDX records
// and returns them as Subdomain values.
//
// The CDX API always returns ["original"] as the first row when output=json
// and fl=original. The header row is identified by its content so that an
// empty result set (no header) is also handled correctly.
//
// Hostnames are extracted using net/url.Parse rather than string splitting
// because archived URLs may contain non-standard port numbers or encoded
// characters that naive splitting would mishandle.
func parseWayBackRecords(records [][]string, targetDomain, source string) []models.Subdomain {
	target := strings.ToLower(strings.TrimSpace(targetDomain))
	seen := make(map[string]struct{})
	var result []models.Subdomain

	for i, record := range records {
		// The CDX API always returns ["original"] as the first element when
		// output=json and fl=original. Skip it so we only process data rows.
		if i == 0 && len(record) > 0 && record[0] == "original" {
			continue
		}
		if len(record) == 0 {
			continue
		}
		u, err := url.Parse(record[0])
		if err != nil || u.Host == "" {
			continue
		}
		// u.Hostname() strips a port number if present ("host:8080" → "host"),
		// which net/url handles correctly regardless of IPv6 brackets.
		name := strings.ToLower(u.Hostname())
		if name == "" {
			continue
		}
		if !inScope(name, target) {
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
