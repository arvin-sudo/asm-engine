// Package models defines the core data types shared across every module of
// the ASM engine. Discovery, scanning, fingerprinting, and storage all speak
// this common language.
//
// Placing models in /pkg (not /internal) means any future external consumer —
// a reporting tool, a CLI wrapper, a web API — can import these types without
// pulling in any business logic.
package models

// Subdomain represents a single hostname discovered during passive recon,
// before it has been resolved to an IP address.
//
// Why keep this separate from Asset? A subdomain is raw intelligence — we know
// the name exists (it appeared in a CT log, a DNS record, etc.) but we have
// not yet confirmed whether it is live or what IPs it points to. Merging raw
// discovery results with fully-resolved assets would collapse two distinct
// pipeline stages into one struct, making it impossible to tell which data has
// been verified and which has not.
type Subdomain struct {
	// Name is the fully-qualified hostname (e.g. "api.example.com").
	Name string

	// Source records which discovery technique found this hostname
	// (e.g. "ct_log", "dns_brute"). Tracking the source lets us later
	// evaluate which technique gives the best coverage for a given target —
	// useful for the performance benchmarking phase of the thesis.
	Source string
}

// IsValid reports whether the subdomain carries a usable hostname.
// A Subdomain with an empty Name cannot be resolved or stored, so callers
// should discard invalid values before passing them to the next pipeline stage.
func (s Subdomain) IsValid() bool {
	return s.Name != ""
}

// Asset is a fully-resolved external asset: a confirmed hostname together with
// all IP addresses it currently resolves to.
//
// An Asset is the enriched output of Phase 1b (DNS resolution). It is the
// primary input to Phase 2 (port scanning) because the scanner needs a concrete
// IP address to open a TCP connection — a hostname alone is not enough.
type Asset struct {
	// Domain is the hostname of the asset (e.g. "api.example.com").
	Domain string

	// IPs holds every A and AAAA record returned for the domain. A single
	// hostname can resolve to multiple addresses (load balancers, CDN anycast
	// nodes), and each IP is an independent attack surface. Storing all of them
	// ensures the scanner does not miss hosts that sit behind a round-robin DNS.
	IPs []string
}

// IsValid reports whether the asset has a non-empty hostname.
func (a Asset) IsValid() bool {
	return a.Domain != ""
}

// Port represents a single open port found on one of an asset's IP addresses.
//
// We store the IP alongside the port number because an Asset can resolve to
// several IPs. Without the IP field, two ports with the same number on
// different hosts would be indistinguishable in the results.
type Port struct {
	// IP is the specific address on which this port was found open.
	IP string

	// Number is the port number (1–65535).
	Number int

	// Proto is the transport-layer protocol — "tcp" or "udp".
	Proto string
}

// Service describes the software running behind an open port, identified by
// reading the service's banner or HTTP response headers during fingerprinting.
//
// Knowing the service name and version is what transforms a raw open port into
// an actionable finding: "port 443 open" is noise, but "Apache 2.4.41 — known
// CVEs apply" is a vulnerability that the client can act on.
type Service struct {
	// Port is the open port on which this service was identified.
	Port Port

	// Name is the service identifier extracted from the banner
	// (e.g. "nginx", "openssh", "apache").
	Name string

	// Version is the version string parsed from the banner (e.g. "2.4.41").
	// Empty means fingerprinting could not determine the version — the port
	// is open but the service did not expose enough information.
	Version string

	// Banner is the raw bytes received from the port — the full HTTP Server
	// header, the SSH greeting, or a proprietary TCP handshake message.
	// Storing the raw banner lets analysts apply custom detection signatures
	// after the fact, without needing to re-scan the target.
	Banner string
}
