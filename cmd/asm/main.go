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
// Current pipeline (Phase 1a + 1b):
//
//	flag --target
//	  → CTDiscoverer.Discover   (passive CT log recon, no target contact)
//	  → DNSResolver.Discover    (resolves each subdomain to live IPs)
//	  → stdout
//
// As subsequent phases are implemented, the pipeline will extend naturally:
//
//	CTDiscoverer → DNSResolver → TCPScanner → Fingerprinter → Store
//
// Each arrow represents one interface boundary. The concrete types wired
// together here will grow, but the inner packages will not need to change.
func main() {
	target := flag.String("target", "", "target domain to scan (required). Example: --target example.com")
	flag.Parse()

	if *target == "" {
		log.Fatal("--target is required. Example: asm-engine --target example.com")
	}

	// Phase 1a — passive recon via Certificate Transparency logs.
	// Declared as the SubdomainDiscoverer interface: this code only calls
	// Discover() and has no access to any CTDiscoverer-specific methods.
	var subdiscoverer discovery.SubdomainDiscoverer = discovery.NewCTDiscoverer(&http.Client{})

	subdomains, err := subdiscoverer.Discover(*target)
	if err != nil {
		log.Fatalf("CT log discovery failed: %v", err)
	}

	fmt.Printf("Found %d subdomains for %s\n\n", len(subdomains), *target)

	// Phase 1b — DNS resolution of discovered hostnames.
	// Declared as the Discoverer interface for the same reason as above.
	var resolver discovery.Discoverer = discovery.NewDNSResolver(discovery.NewNetResolver())

	var liveCount int
	for _, s := range subdomains {
		asset, err := resolver.Discover(s.Name)
		if err != nil {
			// A DNS failure does not abort the run. NXDOMAIN is expected for
			// stale or decommissioned subdomains — those are still worth logging
			// because they can indicate abandoned infrastructure or shadow IT.
			fmt.Printf("  [dead]  %s\n", s.Name)
			continue
		}
		fmt.Printf("  [live]  %-40s %v\n", asset.Domain, asset.IPs)
		liveCount++
	}

	fmt.Printf("\nResolved %d live assets out of %d subdomains.\n", liveCount, len(subdomains))
}
