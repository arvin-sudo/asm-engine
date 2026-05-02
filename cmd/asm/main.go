// Package main is the CLI entry point for the ASM engine.
//
// This file's only responsibility is wiring: read flags from the user,
// construct the concrete implementations, hand them to the appropriate
// interfaces, and print the results. No business logic belongs here.
//
// This follows the Clean Architecture boundary rule: the outermost layer
// (the CLI) is the only place allowed to instantiate concrete types. Every
// inner package (discovery, scanning, storage) depends solely on interfaces,
// which means swapping one implementation for another requires changing
// exactly one line in this file — nothing else.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/arvin-sudo/asm-engine/internal/discovery"
)

// main is the CLI entry point.
//
// Current pipeline (Phase 1a — CT log discovery):
//
//	flag --target  →  CTDiscoverer.Discover  →  stdout
//
// As subsequent phases are implemented, the pipeline will extend naturally:
//
//	CTDiscoverer  →  DNSDiscoverer  →  TCPScanner  →  Fingerprinter  →  Store
//
// Each arrow represents one interface boundary. The concrete types wired
// together here will grow, but the inner packages will not need to change.
func main() {
	target := flag.String("target", "", "target domain to scan (required). Example: --target example.com")
	flag.Parse()

	if *target == "" {
		log.Fatal("--target is required. Example: asm-engine --target example.com")
	}

	// Declare discoverer as the SubdomainDiscoverer interface, not as the
	// concrete *CTDiscoverer type. This enforces the Dependency Inversion
	// Principle at the call site: the code below only calls Discover() — it
	// has no access to any CTDiscoverer-specific methods. If we later swap in
	// a BruteForceDiscoverer, this line is the only change required.
	var discoverer discovery.SubdomainDiscoverer = discovery.NewCTDiscoverer(&http.Client{})

	subdomains, err := discoverer.Discover(*target)
	if err != nil {
		log.Fatalf("discovery failed: %v", err)
	}

	fmt.Printf("Found %d subdomains for %s\n\n", len(subdomains), *target)
	for _, s := range subdomains {
		fmt.Printf("  [%s] %s\n", s.Source, s.Name)
	}
}
