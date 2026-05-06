package discovery

import (
	"context"
	"fmt"
	"sync"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// MultiSourceDiscoverer fans out a single Discover call to N
// SubdomainDiscoverer implementations concurrently and returns the merged,
// deduplicated result.
//
// Why aggregate here rather than in main.go?
// Merging and deduplicating across sources requires a seen-map and error
// accumulation logic. Putting that logic in main.go's wiring layer would
// conflate infrastructure decisions (which sources to run) with business logic
// (how to combine their outputs). MultiSourceDiscoverer keeps main.go clean:
// it sees a single SubdomainDiscoverer and has no knowledge of which concrete
// implementations sit behind it.
//
// Concurrency strategy: each source runs in its own goroutine. Results are
// written to pre-indexed slots (results[i]) — one slot per goroutine — so no
// mutex is needed during collection. After all goroutines finish (sync.WaitGroup),
// the results are merged in original source order. Preserving order is what
// maintains first-source-wins deduplication: if "api.example.com" appears in
// both crt.sh (index 0) and HackerTarget (index 1), the crt.sh record is always
// merged first, so its Source tag wins. With concurrent collection this
// guarantee would be lost; the sequential merge restores it.
//
// Partial failure policy: if one source returns an error its slot is skipped
// and the remaining sources still contribute results. A total failure — every
// source erroring — is reported as a single aggregated error. This mirrors the
// behaviour of a load balancer: one backend failing must not abort the whole
// request.
type MultiSourceDiscoverer struct {
	sources []SubdomainDiscoverer
}

// NewMultiSourceDiscoverer constructs a MultiSourceDiscoverer wrapping the
// provided sources. Sources are queried concurrently. Deduplication preserves
// the first occurrence of each hostname in the original source order, so
// earlier sources take precedence for the Source tag.
func NewMultiSourceDiscoverer(sources ...SubdomainDiscoverer) *MultiSourceDiscoverer {
	return &MultiSourceDiscoverer{sources: sources}
}

// sourceResult holds the outcome of one source's Discover call.
type sourceResult struct {
	subdomains []models.Subdomain
	err        error
}

// Discover queries every registered source concurrently and returns all unique
// subdomains.
//
// ctx is forwarded to every source so that pipeline cancellation (Ctrl+C,
// client disconnect) propagates into all in-flight HTTP requests simultaneously.
// A goroutine whose source respects context cancellation exits promptly;
// one that ignores it will still be bounded by the HTTP client timeout.
//
// Deduplication is by hostname: if "api.example.com" appears in both crt.sh
// and HackerTarget, only the first occurrence (in original source order) is
// kept and its Source tag reflects that source. This preserves accurate
// per-source attribution for coverage analysis.
//
// If every source fails, Discover returns an error describing the total count.
// If only some sources fail, the partial results from the successful sources
// are returned with a nil error — the caller should not need to handle missing
// sources from individual failed discoverers.
func (m *MultiSourceDiscoverer) Discover(ctx context.Context, domain string) ([]models.Subdomain, error) {
	results := make([]sourceResult, len(m.sources))

	var wg sync.WaitGroup
	for i, src := range m.sources {
		wg.Add(1)
		go func(i int, src SubdomainDiscoverer) {
			defer wg.Done()
			found, err := src.Discover(ctx, domain)
			results[i] = sourceResult{subdomains: found, err: err}
		}(i, src)
	}
	wg.Wait()

	// Merge in original source order to preserve first-source-wins deduplication.
	seen := make(map[string]struct{})
	var result []models.Subdomain
	successCount := 0
	for _, r := range results {
		if r.err != nil {
			continue
		}
		successCount++
		for _, sub := range r.subdomains {
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
