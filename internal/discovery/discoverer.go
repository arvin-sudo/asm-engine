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

import "github.com/arvin-sudo/asm-engine/pkg/models"

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
	// An empty result set is not an error — it means the data source had no
	// records for this domain. A non-nil error means the data source itself
	// could not be reached or returned an unexpected response.
	Discover(domain string) ([]models.Subdomain, error)
}

// Discoverer is the contract for resolving a discovered hostname to a full
// Asset with IP addresses. It is used in Phase 1b, after SubdomainDiscoverer
// has produced a list of unverified hostnames.
//
// Keeping resolution as a separate interface means Phase 1b can resolve
// hundreds of subdomains concurrently (one goroutine per hostname) without
// modifying the passive recon code at all. Concurrency is introduced at the
// boundary between the two interfaces, not inside either one.
type Discoverer interface {
	// Discover resolves domain to its current IP addresses and returns it as
	// a fully-populated Asset. Returns an error if DNS resolution fails entirely.
	Discover(domain string) ([]models.Asset, error)
}
