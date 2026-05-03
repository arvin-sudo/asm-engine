package discovery

import (
	"net"
	"strings"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// ptrSource is the source tag written into Subdomain values discovered via
// reverse DNS. It distinguishes PTR-discovered hostnames from passive-recon
// findings (ct_log, hackertarget, wayback) when evaluating per-source coverage.
const ptrSource = "ptr"

// PTRResolver is the interface for reverse DNS (PTR record) lookups.
//
// A separate interface from Resolver (which handles forward A/AAAA lookups)
// follows Interface Segregation: PTREnricher only ever calls LookupAddr, and
// DNSResolver only ever calls LookupHost. Merging them would force every mock
// implementation of either interface to stub a method it never uses.
type PTRResolver interface {
	// LookupAddr performs a reverse DNS lookup on addr and returns the
	// fully-qualified domain names (FQDNs) that PTR records point to.
	// FQDNs carry a trailing dot (e.g. "host.example.com."); callers must
	// strip it before using the name as a forward DNS query target.
	LookupAddr(addr string) ([]string, error)
}

// netPTRResolver is the production PTRResolver. It delegates to net.LookupAddr,
// which queries the system resolver for PTR records.
type netPTRResolver struct{}

func (r *netPTRResolver) LookupAddr(addr string) ([]string, error) {
	return net.LookupAddr(addr)
}

// NewNetPTRResolver returns a PTRResolver backed by the system DNS configuration.
// Pass this to NewPTREnricher in production; inject a mockPTRResolver in tests.
func NewNetPTRResolver() PTRResolver {
	return &netPTRResolver{}
}

// PTREnricher discovers additional hostnames by performing reverse DNS (PTR)
// lookups on a set of IP addresses discovered during Phase 1b.
//
// Why run PTR lookups as a post-resolution enrichment step?
// Passive sources (CT logs, HackerTarget, WayBack) can only find subdomains
// that were publicly recorded at some point. Cloud environments, however,
// often assign PTR records to IPs that point to internal service hostnames or
// sibling services on the same hosting infrastructure — none of which appear
// in public indexes. By querying PTR records on every IP already discovered,
// we extend the attack surface map into the cloud provider's allocation space
// without making any direct probes against the target organisation itself.
type PTREnricher struct {
	resolver PTRResolver
}

// NewPTREnricher constructs a PTREnricher backed by the provided PTRResolver.
func NewPTREnricher(r PTRResolver) *PTREnricher {
	return &PTREnricher{resolver: r}
}

// Enrich performs PTR lookups on each unique IP in ips and returns all
// discovered hostnames as Subdomain values tagged with source "ptr".
//
// Each unique IP is queried exactly once — the input may contain the same
// address multiple times (e.g. an IP shared by two assets in the live list),
// and querying it twice would produce redundant results. PTR lookup failures
// are silently skipped; a missing or broken PTR record is not exceptional —
// many cloud IPs have none.
//
// The caller is responsible for filtering out hostnames that are already known
// (e.g. already present in the live-asset list) before passing them to the
// DNS resolver for forward resolution.
func (e *PTREnricher) Enrich(ips []string) []models.Subdomain {
	seenIPs := make(map[string]struct{})
	seenNames := make(map[string]struct{})
	var result []models.Subdomain

	for _, ip := range ips {
		if _, ok := seenIPs[ip]; ok {
			continue
		}
		seenIPs[ip] = struct{}{}

		names, err := e.resolver.LookupAddr(ip)
		if err != nil {
			continue
		}
		for _, name := range names {
			// net.LookupAddr returns FQDNs with a trailing dot ("host.example.com.").
			// Strip it so the name can be passed directly to a DNS resolver.
			name = strings.ToLower(strings.TrimRight(strings.TrimSpace(name), "."))
			if name == "" {
				continue
			}
			if _, ok := seenNames[name]; ok {
				continue
			}
			seenNames[name] = struct{}{}
			result = append(result, models.Subdomain{Name: name, Source: ptrSource})
		}
	}
	return result
}
