package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// crtshBase is the root URL of the crt.sh Certificate Transparency search API.
//
// Why use crt.sh? Certificate Transparency (CT) logs are public, append-only
// records that every trusted Certificate Authority must publish new TLS
// certificates to. This means any subdomain that has ever had a public TLS
// certificate will appear in a CT log — including forgotten staging servers,
// decommissioned APIs, and shadow IT that the organisation itself may not
// remember. crt.sh aggregates hundreds of CT logs and provides a free,
// unauthenticated API, making it the ideal first source for passive recon.
const crtshBase = "https://crt.sh/"

// ctLogSource is the label written into every Subdomain found by CTDiscoverer.
// Using a named constant instead of a raw string literal means there is exactly
// one place to update if we rename or categorise sources differently later.
const ctLogSource = "ct_log"

// CTDiscoverer implements SubdomainDiscoverer by querying the crt.sh
// Certificate Transparency log API.
//
// It is intentionally unaware of any other discovery technique. Its only
// responsibility is to translate a domain name into a list of hostnames that
// have appeared in public TLS certificates — nothing more, nothing less.
// This strict focus (Single Responsibility) makes the struct straightforward
// to test and safe to modify without side-effects on other modules.
type CTDiscoverer struct {
	// client is the HTTP client used for all outbound requests.
	// It is injected at construction time so that tests can supply a mock
	// without requiring a live network connection.
	client HTTPClient
}

// NewCTDiscoverer constructs a CTDiscoverer backed by the provided HTTP client.
//
// Production usage: pass an *http.Client with a non-zero Timeout. An *http.Client
// with zero Timeout will wait indefinitely if crt.sh is slow or unresponsive —
// always set a deadline for outbound network requests in a CLI tool.
//
// Test usage: pass a *mockHTTPClient that returns predetermined responses.
// This is the Dependency Injection pattern: the caller decides which
// implementation to use; CTDiscoverer never constructs its own dependencies.
func NewCTDiscoverer(c HTTPClient) *CTDiscoverer {
	return &CTDiscoverer{client: c}
}

// crtshEntry is an internal struct that mirrors one element of the JSON array
// crt.sh returns. We decode only the fields we actually use — the API returns
// additional metadata (issuer, serial number, validity dates) that is not
// needed for subdomain discovery.
type crtshEntry struct {
	// NameValue holds the domain name(s) from the certificate's Subject
	// Alternative Names (SANs). When a single certificate covers multiple
	// domains, crt.sh concatenates all of them here, separated by "\n".
	NameValue string `json:"name_value"`
}

// Discover queries crt.sh and returns every unique subdomain of domain that
// has ever appeared in a public TLS certificate.
//
// The method proceeds in three steps:
//  1. Build the query URL and issue the HTTP GET request.
//  2. Validate the HTTP status and stream-decode the JSON response body.
//  3. Delegate parsing and deduplication to parseSubdomains.
//
// ctx is embedded in the outbound request via http.NewRequestWithContext so
// that cancellation (Ctrl+C, client disconnect) propagates into the in-flight
// connection. crt.sh can be slow under rate-limiting; without this the goroutine
// would hang until the HTTP client's own timeout fires.
//
// Errors at each step are wrapped with a "ct_discoverer:" prefix so the caller
// can immediately identify which layer of the pipeline failed without reading
// through stack traces.
func (d *CTDiscoverer) Discover(ctx context.Context, domain string) ([]models.Subdomain, error) {
	// The crt.sh wildcard operator is "%", which must be percent-encoded as
	// "%25" in the query string so the HTTP client transmits it literally.
	// url.QueryEscape handles this correctly and is far more readable than
	// embedding the encoding directly in a format string.
	endpoint := crtshBase + "?q=" + url.QueryEscape("%."+domain) + "&output=json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("ct_discoverer: build request: %w", err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		// A network-level failure: DNS resolution of crt.sh failed, a proxy
		// blocked the connection, or the request timed out before a response
		// arrived. The wrapped error preserves the original for errors.Is checks.
		return nil, fmt.Errorf("ct_discoverer: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// crt.sh returns HTTP 429 when we query too frequently (rate limiting).
		// Other codes (503, 504) indicate a temporary outage on their end.
		// In both cases we cannot trust the response body, so we surface the
		// status code and let the caller decide whether to retry.
		return nil, fmt.Errorf("ct_discoverer: unexpected status %d", resp.StatusCode)
	}

	var entries []crtshEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		// We stream-decode (NewDecoder) rather than read the full body into
		// memory first (json.Unmarshal). For popular domains, crt.sh can
		// return thousands of certificate entries — streaming keeps memory
		// usage flat regardless of response size.
		return nil, fmt.Errorf("ct_discoverer: json decode: %w", err)
	}

	return parseSubdomains(entries, domain, ctLogSource), nil
}

// parseSubdomains converts raw crt.sh entries into a deduplicated slice of
// Subdomain values scoped to targetDomain, each tagged with the provided
// source label.
//
// Why split on "\n"?
// A TLS certificate can secure many domains via Subject Alternative Names
// (SANs). When crt.sh represents such a certificate, it packs all the SANs
// into one name_value string joined by newline characters. Without splitting,
// "*.example.com\nexample.com" would be stored as a single malformed hostname
// instead of two valid, independently actionable ones.
//
// Why filter by targetDomain?
// A certificate returned by crt.sh for "%.example.com" can include SANs for
// entirely unrelated domains (e.g. a multi-tenant cert that covers both
// "api.example.com" and "other.org"). Without filtering, those unrelated
// domains leak into the results — the DNS resolver queries them and the output
// lists them as findings under the wrong target. Only names that equal or are
// direct subdomains of targetDomain are kept.
//
// Why deduplicate?
// The same hostname frequently appears across dozens of certificates —
// annual renewals, wildcard certs, multi-domain certs all produce duplicate
// entries. Deduplicating here prevents the downstream DNS resolver from making
// redundant network calls for the same host.
//
// Why is source a parameter instead of being hardcoded?
// parseSubdomains has a single job: parse and deduplicate. Deciding what label
// to attach belongs to the caller, not to a utility function. This keeps the
// function reusable for any HTTP-based source without modification.
func parseSubdomains(entries []crtshEntry, targetDomain, source string) []models.Subdomain {
	// Normalise once so every comparison is against a consistent baseline.
	target := strings.ToLower(strings.TrimSpace(targetDomain))

	// seen is used as a set: O(1) average-case lookup to check whether a
	// hostname has already been added. The empty struct value costs zero bytes,
	// so the map tracks membership without wasting memory on placeholder values.
	seen := make(map[string]struct{})

	// Pre-allocate using the entry count as a lower-bound capacity hint.
	// The actual count after SAN splitting may be higher, and after
	// deduplication it may be lower, but this avoids the most expensive
	// early re-allocations when the result set is large.
	result := make([]models.Subdomain, 0, len(entries))

	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			// Normalize to lowercase before any further processing.
			// DNS names are case-insensitive (RFC 4343), so "API.example.com"
			// and "api.example.com" are the same host. Without normalization,
			// the deduplication map treats them as distinct entries — the DNS
			// resolver then makes redundant calls and the output lists the same
			// host twice under different capitalizations.
			name = strings.ToLower(strings.TrimSpace(name))

			// Skip blank lines that can appear between SANs in malformed entries.
			if name == "" {
				continue
			}

			// Discard SANs outside the target scope — see inScope for the
			// full rationale. A multi-tenant certificate covers unrelated
			// domains; without this guard they would pollute the results.
			if !inScope(name, target) {
				continue
			}

			// Skip hostnames we have already added to the result.
			if _, exists := seen[name]; exists {
				continue
			}

			seen[name] = struct{}{}
			result = append(result, models.Subdomain{Name: name, Source: source})
		}
	}

	return result
}
