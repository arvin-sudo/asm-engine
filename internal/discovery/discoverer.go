// Package discovery contains the interfaces and implementations for Stage 1
// of the ASM pipeline: finding every hostname associated with a target domain.
//
// The discovery stage is split into two deliberate steps:
//
//  1. Passive recon (SubdomainDiscoverer) — find hostnames by querying public
//     third-party data sources. The target is never contacted directly.
//
//  2. Resolution (Discoverer) — take each discovered hostname and resolve it
//     to IP addresses, confirming the host is live and ready for port scanning.
//
// Separating these into two interfaces means each step can evolve independently.
// A new CT log source or a DNS brute-force module can be plugged into step 1
// without touching the DNS resolver in step 2, and vice versa.
package discovery

import (
	"context"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// SubdomainDiscoverer is the contract for any passive recon technique that
// finds hostnames associated with a target domain.
//
// Implementations must not actively probe the target — they may only query
// public third-party sources (certificate logs, WHOIS records, DNS datasets).
// This constraint keeps Phase 1a safe to run without the target's knowledge
// and avoids generating traffic that could trigger an intrusion detection alert.
type SubdomainDiscoverer interface {
	// Discover returns all hostnames for domain found by this implementation.
	//
	// ctx allows the pipeline to cancel an in-flight request — for example,
	// when the user presses Ctrl+C or closes the browser tab. Implementations
	// must build HTTP requests with http.NewRequestWithContext(ctx, ...) so the
	// cancellation propagates into the underlying transport and the goroutine
	// exits promptly instead of waiting for a slow external API to respond.
	//
	// An empty result set is not an error — it means the data source had no
	// records for this domain. A non-nil error means the data source itself
	// could not be reached or returned an unexpected response.
	Discover(ctx context.Context, domain string) ([]models.Subdomain, error)
}

// Discoverer is the contract for resolving a discovered hostname to a full
// Asset with IP addresses. It is used in Phase 1b, after SubdomainDiscoverer
// has produced a list of unverified hostnames.
//
// Keeping resolution as a separate interface means Phase 1b can evolve
// independently of passive recon. The caller (main.go or a future orchestrator)
// decides how to iterate over subdomains — sequentially now, with a worker pool
// in Phase 2 when scanning volume makes the cost measurable. Neither this
// interface nor its implementations need to change when that decision is made.
type Discoverer interface {
	// Discover resolves domain to its current IP addresses and returns a
	// fully-populated Asset. Returns an error if DNS resolution fails.
	//
	// A single domain maps to exactly one Asset — Asset.IPs already holds
	// all the addresses the domain resolves to. Returning a slice here would
	// conflate "multiple IPs for one host" with "multiple hosts", which are
	// two different concepts at different pipeline stages.
	Discover(domain string) (models.Asset, error)
}
