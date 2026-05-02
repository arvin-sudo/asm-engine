package discovery

import (
	"fmt"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// DNSResolver implements Discoverer by resolving each hostname to its current
// IP addresses via the system DNS resolver.
//
// It is the Phase 1b component of the discovery pipeline. Its only job is to
// take a hostname that Phase 1a (CTDiscoverer) found in a CT log and confirm
// whether it is currently live by performing an A/AAAA lookup. A host that
// returns NXDOMAIN is reported as an error rather than silently dropped —
// a dead subdomain is meaningful intelligence because it may indicate a
// recently decommissioned asset that still has open firewall rules or stale
// DNS entries elsewhere.
type DNSResolver struct {
	// resolver is the DNS lookup dependency. Injected at construction time
	// so that tests can supply a mockResolver without touching the network.
	resolver Resolver
}

// NewDNSResolver constructs a DNSResolver backed by the provided Resolver.
//
// Production: pass NewNetResolver() — it delegates to net.LookupHost.
// Tests: pass a *mockResolver that returns predetermined addresses or errors.
func NewDNSResolver(r Resolver) *DNSResolver {
	return &DNSResolver{resolver: r}
}

// Discover resolves domain to its current IP addresses and returns a
// fully-populated Asset ready for the port-scanning stage (Phase 2).
//
// Errors are wrapped with a "dns_resolver:" prefix so a caller iterating over
// many subdomains can immediately identify which layer of the pipeline failed
// without reading through the full error chain.
func (d *DNSResolver) Discover(domain string) (models.Asset, error) {
	ips, err := d.resolver.LookupHost(domain)
	if err != nil {
		return models.Asset{}, fmt.Errorf("dns_resolver: lookup %q: %w", domain, err)
	}
	return models.Asset{Domain: domain, IPs: deduplicateIPs(ips)}, nil
}

// deduplicateIPs returns ips with duplicate values removed, preserving order.
//
// net.LookupHost can return the same address more than once in some resolver
// configurations (e.g. when both an A and a synthesised AAAA record resolve to
// the same underlying address). Without deduplication, the scanner probes the
// same host twice and the output prints duplicate result blocks for the same IP.
func deduplicateIPs(ips []string) []string {
	seen := make(map[string]struct{}, len(ips))
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		result = append(result, ip)
	}
	return result
}
