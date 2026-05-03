package discovery

import (
	"fmt"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// MultiSourceDiscoverer fans out a single Discover call to N
// SubdomainDiscoverer implementations and returns the merged, deduplicated
// result.
//
// Why aggregate here rather than in main.go?
// Merging and deduplicating across sources requires a seen-map and error
// accumulation logic. Putting that logic in main.go's wiring layer would
// conflate infrastructure decisions (which sources to run) with business logic
// (how to combine their outputs). MultiSourceDiscoverer keeps main.go clean:
// it sees a single SubdomainDiscoverer and has no knowledge of which concrete
// implementations sit behind it.
//
// Partial failure policy: if one source returns an error its results are
// silently skipped and the remaining sources are still queried. A total
// failure — every source erroring — is reported as a single aggregated error.
// This mirrors the behaviour of a load balancer: one backend failing must not
// abort the whole request.
type MultiSourceDiscoverer struct {
	sources []SubdomainDiscoverer
}

// NewMultiSourceDiscoverer constructs a MultiSourceDiscoverer wrapping the
// provided sources. Sources are queried in the order they are given.
// Deduplication preserves the first occurrence of each hostname, so earlier
// sources take precedence for the Source tag — the source that originally
// found a name is the one recorded in Subdomain.Source.
func NewMultiSourceDiscoverer(sources ...SubdomainDiscoverer) *MultiSourceDiscoverer {
	return &MultiSourceDiscoverer{sources: sources}
}

// Discover queries every registered source and returns all unique subdomains.
//
// Deduplication is by hostname: if "api.example.com" appears in both crt.sh
// and HackerTarget, only the first occurrence is kept and its Source tag
// reflects that source. This preserves accurate per-source attribution for
// coverage analysis.
//
// If every source fails, Discover returns an error describing the total count.
// If only some sources fail, the partial results from the successful sources
// are returned with a nil error — the caller should not need to handle missing
// sources from individual failed discoverers.
func (m *MultiSourceDiscoverer) Discover(domain string) ([]models.Subdomain, error) {
	seen := make(map[string]struct{})
	var result []models.Subdomain
	successCount := 0

	for _, src := range m.sources {
		found, err := src.Discover(domain)
		if err != nil {
			continue
		}
		successCount++
		for _, sub := range found {
			if _, ok := seen[sub.Name]; ok {
				continue
			}
			seen[sub.Name] = struct{}{}
			result = append(result, sub)
		}
	}

	if successCount == 0 && len(m.sources) > 0 {
		return nil, fmt.Errorf("multi_source_discoverer: all %d source(s) failed for %q", len(m.sources), domain)
	}
	return result, nil
}
