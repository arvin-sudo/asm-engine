// Package fingerprint defines the interface for Phase 2b of the ASM pipeline:
// identifying the software and version running behind an open port.
//
// Fingerprinting is separated from port scanning because the two operations
// have different failure modes and timeout requirements. The scanner cares only
// about whether a TCP connection is accepted. The fingerprinter cares about
// the content of the response — banner text, HTTP Server headers, TLS
// certificate metadata. Separating them into distinct packages means each can
// be tuned, tested, and extended without risk of breaking the other.
package fingerprint

import "github.com/arvin-sudo/asm-engine/pkg/models"

// Fingerprinter is the contract for any banner-grabbing or service-detection
// technique.
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
