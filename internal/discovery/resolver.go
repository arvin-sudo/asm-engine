package discovery

import "net"

// Resolver is the interface for DNS host-name lookup used by DNSResolver.
//
// Why not depend on net.Resolver directly?
// net.Resolver is a concrete struct whose LookupHost method requires a
// context.Context. Accepting it as a dependency would force every caller and
// every test to construct a context, adding noise before we need cancellation.
// This narrow, context-free interface keeps the test doubles to a single method
// and defers context handling to the day we actually measure a timeout problem.
type Resolver interface {
	// LookupHost resolves host to a list of IP address strings (both A and
	// AAAA records). Returns an error if the host does not exist (NXDOMAIN)
	// or if the local resolver is unreachable.
	LookupHost(host string) ([]string, error)
}

// netResolver is the production Resolver. It wraps net.LookupHost, which
// consults the system DNS configuration (resolv.conf on Linux, DNS APIs on
// macOS/Windows). The struct is unexported because callers only need the
// Resolver interface — the concrete type is an implementation detail.
type netResolver struct{}

// LookupHost resolves host using the system resolver. It returns every A and
// AAAA address the system DNS provides, preserving the order returned by the
// resolver (which may reflect round-robin DNS load balancing).
func (r *netResolver) LookupHost(host string) ([]string, error) {
	return net.LookupHost(host)
}

// NewNetResolver returns a Resolver backed by the system DNS configuration.
//
// Pass this to NewDNSResolver in production. In tests, inject a mockResolver
// that returns controlled responses without touching the network.
func NewNetResolver() Resolver {
	return &netResolver{}
}
