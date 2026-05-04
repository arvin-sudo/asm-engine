// Package fingerprint defines the interfaces and implementations for Phase 2b
// of the ASM pipeline: identifying the software and version running behind an
// open port, and — for HTTP/HTTPS services — the web technology stack.
//
// Two complementary fingerprinting strategies are provided:
//
//   - Fingerprinter (BannerFingerprinter): reads the service's greeting or
//     issues an HTTP HEAD request. Fast, works on all protocols, but limited
//     to what the Server header reveals. Does not need the domain name.
//
//   - WebFingerprinter (WebStackFingerprinter): issues a full HTTP GET with
//     the correct Host header and inspects both response headers and HTML body
//     for framework/CMS signatures. Requires the domain name. Intended for
//     HTTP and HTTPS ports only, run after BannerFingerprinter has confirmed
//     the port speaks HTTP.
//
// Separating the two interfaces follows Interface Segregation: callers that
// only need service identification (for vulnerability mapping) depend on
// Fingerprinter; callers that additionally want technology stack data depend
// on WebFingerprinter.
package fingerprint

import "github.com/arvin-sudo/asm-engine/pkg/models"

// Fingerprinter is the contract for banner-grabbing and service detection.
//
// Why accept a Port struct rather than separate IP, number, and protocol args?
// The Port struct already bundles the three values a fingerprinter needs to
// establish a connection. Accepting them as a single struct keeps the method
// signature stable — if we later add fields to Port (e.g. a timeout hint),
// no fingerprinter caller needs to be updated.
type Fingerprinter interface {
	// Fingerprint connects to port and attempts to identify the service running
	// on it by reading its greeting, banner, or HTTP headers.
	//
	// It always returns a Service, even when identification is inconclusive.
	// In that case, Name and Version will be empty strings and Banner will
	// contain whatever raw bytes were received — preserving the evidence for
	// manual analysis without treating ambiguity as a failure.
	Fingerprint(port models.Port) (models.Service, error)
}

// WebFingerprinter identifies the web technology stack running on an HTTP or
// HTTPS port by issuing a full GET request with the correct Host header and
// inspecting both response headers and HTML body content.
//
// Why a separate interface from Fingerprinter?
// Fingerprinter.Fingerprint only receives a Port (IP + number + proto) — no
// hostname. Without the hostname the Host header must be set to the IP address,
// which causes virtual-hosting servers to return their default vhost response
// instead of the intended site. WebFingerprinter resolves this by explicitly
// accepting the domain name, enabling precise Host header injection and
// full-page content analysis.
//
// Only call FingerprintWeb on ports confirmed to speak HTTP or HTTPS — passing
// a database port will produce an error or an empty result.
type WebFingerprinter interface {
	// FingerprintWeb issues a GET / request to port with the Host header set
	// to domain and returns all technology signatures matched against the
	// response headers and HTML body.
	//
	// Returns an empty slice (not an error) when the port is reachable but no
	// known technology signatures are detected. Returns an error only when the
	// TCP connection or TLS handshake fails.
	FingerprintWeb(domain string, port models.Port) ([]models.Technology, error)

	// CanFingerprint reports whether portNum falls within this fingerprinter's
	// HTTP or HTTPS port routing table. Callers use this to gate web
	// fingerprinting without duplicating port lists in the wiring layer —
	// the fingerprinter owns knowledge of which ports speak HTTP.
	CanFingerprint(portNum int) bool
}
