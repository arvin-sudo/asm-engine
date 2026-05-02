// Package scanner defines the interface for Phase 2 of the ASM pipeline:
// probing discovered assets for open TCP and UDP ports.
//
// Port scanning is isolated in its own package because it has fundamentally
// different performance characteristics from discovery. Discovery is I/O-bound
// (waiting for HTTP responses from third-party APIs). Scanning is network-bound
// and benefits heavily from concurrency — probing 65 535 ports sequentially on
// a single host is far too slow. Isolating the scanner here means we can
// introduce a worker-pool / goroutine-based implementation in Phase 2 without
// touching any of the discovery code.
package scanner

import "github.com/arvin-sudo/asm-engine/pkg/models"

// Scanner is the contract for any port-probing technique.
//
// Why accept a full Asset rather than just an IP string?
// An asset can resolve to multiple IP addresses (load balancers, CDN anycast
// nodes). Accepting the entire Asset gives each implementation the flexibility
// to decide which IPs to probe and how — for example, a smart implementation
// might probe only the first IP to keep scan time predictable, while a thorough
// one might probe all of them. This decision stays inside the implementation
// without changing the interface.
type Scanner interface {
	// Scan probes asset for open ports and returns one Port value for each
	// port that accepted a connection.
	//
	// A closed or filtered port is not an error — it is an expected and normal
	// outcome. An error is returned only when something prevented scanning
	// from running at all, such as a local network failure or an invalid asset.
	Scan(asset models.Asset) ([]models.Port, error)
}
