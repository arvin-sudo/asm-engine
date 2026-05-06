// Package models defines the core data types shared across every module of
// the ASM engine. Discovery, scanning, fingerprinting, and storage all speak
// this common language.
//
// Placing models in /pkg (not /internal) means any future external consumer —
// a reporting tool, a CLI wrapper, a web API — can import these types without
// pulling in any business logic.
package models

import (
	"strings"
	"time"
)

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

// IsWildcard reports whether this subdomain is a wildcard entry (e.g. "*.example.com").
//
// Wildcard hostnames appear in CT logs because TLS wildcard certificates cover
// all first-level subdomains under a domain. The entry is real intelligence —
// it proves the organisation issued a wildcard cert — but the name itself is
// not a valid DNS hostname and cannot be passed to the DNS resolver. Callers
// use this method to route wildcards to a separate output category instead of
// letting them fail as spurious DNS errors.
func (s Subdomain) IsWildcard() bool {
	return strings.HasPrefix(s.Name, "*.")
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
	//
	// Invariant: IPs contains no duplicates. The DNSResolver deduplicates before
	// returning an Asset; callers must not append to IPs without checking for
	// existing entries, as a duplicate IP causes the port scanner to scan the
	// same host twice and produces duplicate findings.
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

	// Vulnerabilities holds CVEs matched against this service's name and
	// version by the vulnerability database during the current scan run.
	// This field is populated in-memory and is never persisted — CVE
	// applicability is recomputed fresh on every run from the built-in
	// dataset, ensuring results always reflect the current state of the
	// vulnerability database rather than a stale snapshot from a past scan.
	Vulnerabilities []Vulnerability
}

// BucketResult is a cloud storage bucket probed during Phase 3 (cloud bucket hunting).
//
// Why keep this in pkg/models rather than internal/cloudscan? Phase 4
// (PostgreSQL persistence) needs to store bucket findings alongside asset
// records. If BucketResult lived inside cloudscan, the storage layer would
// have to import a business-logic package — violating the dependency rule that
// says inner layers must not know about outer ones. Placing it here keeps both
// the scanner and the storage layer independent of each other.
type BucketResult struct {
	// URL is the full endpoint that was probed
	// (e.g. "https://example.s3.amazonaws.com").
	URL string

	// Provider identifies the cloud platform: "aws_s3" or "azure_blob".
	Provider string

	// Status is the HTTP status code returned by the HEAD request.
	// 200 = publicly accessible; 403 = exists but private.
	Status int

	// Accessible reports whether the bucket responded with 200 OK, meaning
	// any unauthenticated request can list or read its contents. A 403 means
	// the bucket exists but requires authentication — still a finding because
	// it confirms the storage asset is real.
	Accessible bool
}

// ServiceIndicator represents a third-party service integration discovered from
// the target domain's DNS records during Phase 1d (DNS intelligence).
//
// Third-party services revealed by DNS records represent an indirect attack
// surface: a compromised Mailgun account can be used to send phishing emails
// from the target domain, and a misconfigured Zendesk integration can expose
// internal ticket data. Mapping these integrations is part of understanding
// the full blast radius of the target's external exposure.
type ServiceIndicator struct {
	// Service is the human-readable name of the identified third-party service
	// (e.g. "Mailgun", "Microsoft 365", "Zendesk").
	Service string

	// Record is the DNS record type that revealed the integration: "TXT" or "MX".
	Record string

	// Evidence is the raw DNS record value that matched, preserved for manual
	// review in case the automatic classification is incorrect or ambiguous.
	Evidence string
}

// Technology is a web framework, CMS, programming language, or library
// identified from HTTP response headers or HTML content during Phase 2b
// technology stack fingerprinting.
//
// Knowing the technology stack transforms a bare open port into an actionable
// finding: "443/tcp nginx" is noise, but "443/tcp nginx — WordPress 6.4 + PHP 8.1"
// tells an analyst which exploit chains to prioritise. Technology identification
// also catches cases where the Server header is suppressed — a WordPress site
// behind a CDN that hides the server name is still detectable from wp-content
// paths in the HTML.
//
// Technology lives in pkg/models because cmd/asm/main.go needs to print it
// alongside Service, and internal/fingerprint produces it. Keeping it here
// avoids either package importing the other.
type Technology struct {
	// Name is the human-readable technology identifier (e.g. "WordPress", "PHP",
	// "React", "Next.js").
	Name string

	// Category classifies the technology's role in the stack: "CMS",
	// "Framework", "Language", "Server", or "Platform".
	Category string

	// Evidence is the HTTP header value or HTML pattern that triggered the
	// match, preserved for manual review in case the classification is wrong.
	// Example: "X-Powered-By: PHP/8.1.2" or "HTML: wp-content path detected".
	Evidence string
}

// AssetRecord wraps a fully-resolved Asset with the persistence metadata
// maintained by the storage layer.
//
// Why not embed timestamps directly in Asset? Asset is a domain concept:
// a hostname and its current IP addresses. Timestamps are a persistence
// concept: when a particular scanner observed those addresses. Merging them
// would force every part of the pipeline (scanner, fingerprinter, cloud scan)
// to carry timestamp state they have no use for. AssetRecord is returned only
// by Store.FindAssets — it never enters the discovery or scanning stages.
type AssetRecord struct {
	// Asset embeds the domain and IP data so callers can access record.Domain
	// and record.IPs directly without an extra field dereference.
	Asset

	// FirstSeen is the timestamp of the earliest scan run that discovered this
	// asset. It is set once and never overwritten by subsequent scans.
	FirstSeen time.Time

	// LastSeen is the timestamp of the most recent scan run that observed this
	// asset. A large gap between FirstSeen and LastSeen combined with a
	// LastSeen that lags behind today indicates the asset may have disappeared
	// from the attack surface.
	LastSeen time.Time
}
