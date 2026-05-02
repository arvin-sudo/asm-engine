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
	"strings"
	"time"

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

	// TrimSpace guards against "--target '  '" (whitespace-only) slipping
	// through the empty-string check and being forwarded to crt.sh.
	domain := strings.TrimSpace(*target)
	if domain == "" {
		log.Fatal("--target is required. Example: asm-engine --target example.com")
	}

	// Phase 1a — passive recon via Certificate Transparency logs.
	// Declared as the SubdomainDiscoverer interface: this code only calls
	// Discover() and has no access to any CTDiscoverer-specific methods.
	// A 30-second timeout prevents the CLI from hanging indefinitely if
	// crt.sh is slow or unresponsive. Zero timeout (the default) means wait
	// forever, which gives the user no feedback and no way to recover short
	// of killing the process.
	var subdiscoverer discovery.SubdomainDiscoverer = discovery.NewCTDiscoverer(&http.Client{
		Timeout: 30 * time.Second,
	})

	subdomains, err := subdiscoverer.Discover(domain)
	if err != nil {
		log.Fatalf("CT log discovery failed: %v", err)
	}

	fmt.Printf("Found %d subdomains for %s\n\n", len(subdomains), domain)

	// Phase 1b — DNS resolution of discovered hostnames.
	// Declared as the Discoverer interface for the same reason as above.
	var resolver discovery.Discoverer = discovery.NewDNSResolver(discovery.NewNetResolver())

	var liveCount, wildcardCount int
	for _, s := range subdomains {
		// Wildcards (e.g. "*.example.com") are not valid DNS hostnames and
		// will always produce a resolver error. They are real intelligence —
		// they prove a wildcard cert was issued — but routing them through
		// the DNS resolver would misreport them as dead hosts.
		if s.IsWildcard() {
			fmt.Printf("  [wildcard]  %s\n", s.Name)
			wildcardCount++
			continue
		}

		asset, err := resolver.Discover(s.Name)
		if err != nil {
			// NXDOMAIN is expected for stale or decommissioned subdomains.
			// They are still worth logging as they can indicate abandoned
			// infrastructure or shadow IT with stale DNS entries.
			fmt.Printf("  [dead]      %s\n", s.Name)
			continue
		}
		fmt.Printf("  [live]      %-40s %s\n", asset.Domain, strings.Join(asset.IPs, ", "))
		liveCount++
	}

	fmt.Printf("\nResults: %d live, %d wildcard, %d dead — %d total subdomains discovered.\n",
		liveCount, wildcardCount, len(subdomains)-liveCount-wildcardCount, len(subdomains))
}
