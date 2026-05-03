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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arvin-sudo/asm-engine/internal/cloudscan"
	"github.com/arvin-sudo/asm-engine/internal/discovery"
	"github.com/arvin-sudo/asm-engine/internal/fingerprint"
	"github.com/arvin-sudo/asm-engine/internal/scanner"
	"github.com/arvin-sudo/asm-engine/internal/storage"
	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// defaultPorts is the set of TCP ports probed when --ports is not specified.
//
// The selection covers services most commonly exposed on an external attack
// surface: web servers, SSH, database engines, remote desktop, and popular
// NoSQL stores. This is deliberately narrower than nmap's top-1000 list —
// the goal is fast, signal-rich output rather than exhaustive enumeration.
var defaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
	993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017,
}

// main is the CLI entry point.
//
// Full pipeline (Phases 1–4):
//
//	flag --target
//	  → CTDiscoverer.Discover            (passive CT log recon, no target contact)
//	  → DNSResolver.Discover             (resolves each subdomain to live IPs)
//	  → store.SaveAsset                  (Phase 4: persist live asset, optional)
//	  → TCPScanner.Scan                  (probes open TCP ports with a worker pool)
//	  → store.SavePort                   (Phase 4: persist each open port)
//	  → BannerFingerprinter.Fingerprint  (reads service banners / HTTP headers)
//	  → store.SaveService                (Phase 4: persist identified service)
//	  → BucketHunter.Scan               (probes cloud storage URL patterns)
//	  → store.SaveBucket                 (Phase 4: persist bucket findings)
//	  → stdout
//
// All store calls are guarded by a nil check — when --db is not supplied the
// store is nil and the pipeline runs as a pure stdout tool with no side effects.
func main() {
	// Strip the default date/time prefix from log output. A CLI tool should
	// print clean error messages — timestamps belong in structured log files,
	// not in terminal error lines read by a human.
	log.SetFlags(0)

	target := flag.String("target", "", "target domain to scan (required). Example: --target example.com")
	portsFlag := flag.String("ports", "", "comma-separated TCP ports to scan. Default: 21 common ports.")
	workersFlag := flag.Int("workers", 100, "number of concurrent goroutines for port scanning")
	timeoutFlag := flag.Duration("scan-timeout", 2*time.Second, "per-connection timeout for port scanning and fingerprinting")
	dbFlag := flag.String("db", "", "PostgreSQL DSN for persistence, e.g. postgres://user:pass@localhost/asmdb?sslmode=disable. Omit to disable persistence.")
	flag.Parse()

	// Normalise the domain once at the entry point.
	// • TrimSpace removes accidental whitespace around the flag value.
	// • TrimRight removes a trailing dot (FQDN notation: "example.com.").
	//   Without this, the crt.sh query becomes "%.example.com." and the scope
	//   filter in parseSubdomains computes target = "example.com.", which never
	//   matches lowercased results like "api.example.com" — silently returning
	//   zero subdomains for any target written in FQDN form.
	// • ToLower avoids case mismatches in the scope filter and bucket-name
	//   candidates; DNS and crt.sh are both case-insensitive.
	domain := strings.ToLower(strings.TrimRight(strings.TrimSpace(*target), "."))
	if domain == "" {
		log.Fatal("--target is required. Example: asm-engine --target example.com")
	}

	ports, err := parsePorts(*portsFlag)
	if err != nil {
		log.Fatalf("--ports: %v", err)
	}

	// -------------------------------------------------------------------------
	// Phase 4 — optional PostgreSQL persistence.
	// -------------------------------------------------------------------------
	// store is typed as the Store interface so any future implementation
	// (in-memory, SQLite, remote API) can be swapped in without touching the
	// pipeline below. When --db is absent, store remains nil and every save
	// call is skipped — the pipeline behaves identically to pre-Phase 4.
	var store storage.Store
	if *dbFlag != "" {
		ps, err := storage.NewPostgresStore(*dbFlag)
		if err != nil {
			log.Fatalf("store: %v", err)
		}
		defer ps.Close()
		store = ps
		fmt.Printf("Persistence enabled — connected to database.\n\n")
	}

	// -------------------------------------------------------------------------
	// Phase 1a — passive recon via Certificate Transparency logs.
	// -------------------------------------------------------------------------
	// Declared as the SubdomainDiscoverer interface: this code only calls
	// Discover() and has no access to any CTDiscoverer-specific methods.
	// A 30-second timeout prevents the CLI from hanging indefinitely if
	// crt.sh is slow or unresponsive.
	var subdiscoverer discovery.SubdomainDiscoverer = discovery.NewCTDiscoverer(&http.Client{
		Timeout: 30 * time.Second,
	})

	subdomains, err := subdiscoverer.Discover(domain)
	if err != nil {
		log.Fatalf("CT log discovery failed: %v", err)
	}

	fmt.Printf("Found %d subdomains for %s\n\n", len(subdomains), domain)

	// -------------------------------------------------------------------------
	// Phase 1b — DNS resolution of discovered hostnames.
	// -------------------------------------------------------------------------
	var resolver discovery.Discoverer = discovery.NewDNSResolver(discovery.NewNetResolver())

	var liveAssets []models.Asset
	var wildcardCount int

	for _, s := range subdomains {
		// Wildcards (e.g. "*.example.com") are not valid DNS hostnames and
		// will always produce a resolver error. They are still valuable
		// intelligence — they prove a wildcard certificate was issued — so
		// they are reported separately rather than silently discarded.
		if s.IsWildcard() {
			fmt.Printf("  [wildcard]  %s\n", s.Name)
			wildcardCount++
			continue
		}

		asset, err := resolver.Discover(s.Name)
		if err != nil {
			// NXDOMAIN is expected for stale or decommissioned subdomains.
			// Dead entries are worth logging: they may indicate abandoned
			// infrastructure or shadow IT with stale DNS records.
			fmt.Printf("  [dead]      %s\n", s.Name)
			continue
		}
		fmt.Printf("  [live]      %-40s %s\n", asset.Domain, strings.Join(asset.IPs, ", "))
		liveAssets = append(liveAssets, asset)
		if store != nil {
			if err := store.SaveAsset(asset); err != nil {
				log.Printf("store: save asset %q: %v", asset.Domain, err)
			}
		}
	}

	deadCount := len(subdomains) - len(liveAssets) - wildcardCount
	fmt.Printf("\nResults: %d live, %d wildcard, %d dead — %d total subdomains discovered.\n",
		len(liveAssets), wildcardCount, deadCount, len(subdomains))

	// -------------------------------------------------------------------------
	// Phase 2 — TCP port scanning + service fingerprinting.
	// -------------------------------------------------------------------------
	// Guarded: bucket hunting (Phase 3) is domain-based and runs regardless of
	// whether any live assets were found. Port scanning requires a live IP, so
	// it is skipped when the asset list is empty.
	if len(liveAssets) > 0 {
		// Declared as the Scanner and Fingerprinter interfaces so that Phase 4
		// tests can inject in-memory doubles without changing this file.
		fmt.Printf("\nScanning %d port(s) on %d live asset(s) — %d workers, %v timeout...\n\n",
			len(ports), len(liveAssets), *workersFlag, *timeoutFlag)

		var tcpScanner scanner.Scanner = scanner.NewTCPScanner(ports, *timeoutFlag, *workersFlag)

		// Give fingerprinting one extra second beyond the scan timeout. The scan
		// timeout only needs to confirm a port is open (one RTT). Fingerprinting
		// requires a full request-response cycle, so a slightly longer window
		// avoids false "no banner" results on services with high initial latency.
		var fingerprinter fingerprint.Fingerprinter = fingerprint.NewBannerFingerprinter(
			*timeoutFlag+time.Second, 4096,
		)

		totalOpen := 0
		for _, asset := range liveAssets {
			openPorts, err := tcpScanner.Scan(asset)
			if err != nil {
				fmt.Printf("  [scan error] %s: %v\n\n", asset.Domain, err)
				continue
			}
			if len(openPorts) == 0 {
				fmt.Printf("  %s — no open ports found\n\n", asset.Domain)
				continue
			}

			// Sort results so output is deterministic regardless of goroutine
			// scheduling order. Primary key: IP address. Secondary: port number.
			sort.Slice(openPorts, func(i, j int) bool {
				if openPorts[i].IP != openPorts[j].IP {
					return openPorts[i].IP < openPorts[j].IP
				}
				return openPorts[i].Number < openPorts[j].Number
			})

			fmt.Printf("  %s\n", asset.Domain)
			for _, ip := range asset.IPs {
				portsForIP := filterByIP(openPorts, ip)
				if len(portsForIP) == 0 {
					continue
				}
				fmt.Printf("    [%s]\n", ip)
				for _, p := range portsForIP {
					totalOpen++
					// Persist the open port before fingerprinting. SavePort must
					// precede SaveService to satisfy the foreign-key constraint —
					// a service row references its port row.
					if store != nil {
						if err := store.SavePort(asset.Domain, p); err != nil {
							log.Printf("store: save port %s:%d: %v", p.IP, p.Number, err)
						}
					}
					svc, err := fingerprinter.Fingerprint(p)
					if err != nil || svc.Name == "" {
						// Port is open but we could not identify the service.
						// Print what we know rather than hiding the finding.
						fmt.Printf("      %d/tcp   open\n", p.Number)
						continue
					}
					if store != nil {
						if err := store.SaveService(asset.Domain, svc); err != nil {
							log.Printf("store: save service %s:%d: %v", svc.Port.IP, svc.Port.Number, err)
						}
					}
					if svc.Version != "" {
						fmt.Printf("      %d/tcp   %-14s %s\n", p.Number, svc.Name, svc.Version)
					} else {
						fmt.Printf("      %d/tcp   %s\n", p.Number, svc.Name)
					}
				}
			}
			fmt.Println()
		}

		fmt.Printf("Phase 2 complete: %d open port(s) across %d live asset(s).\n",
			totalOpen, len(liveAssets))
	}

	// -------------------------------------------------------------------------
	// Phase 3 — cloud storage bucket hunting.
	// -------------------------------------------------------------------------
	// A dedicated HTTP client with a longer timeout than the port scanner.
	// Cloud storage endpoints resolve immediately (they are always available),
	// but a 10-second window guards against high-latency paths without making
	// the CLI feel frozen. This client is intentionally separate from the one
	// used in Phase 1a: that one needs Get; this one needs Head. Sharing a
	// client would require one of the interfaces to grow a method it never uses.
	fmt.Printf("\nScanning cloud buckets for %s...\n\n", domain)

	var bucketHunter cloudscan.CloudScanner = cloudscan.NewBucketHunter(&http.Client{
		Timeout: 10 * time.Second,
	})

	buckets, err := bucketHunter.Scan(domain)
	if err != nil {
		log.Printf("cloud bucket scan failed: %v", err)
	} else {
		var publicCount, privateCount int
		for _, b := range buckets {
			if store != nil {
				if err := store.SaveBucket(domain, b); err != nil {
					log.Printf("store: save bucket %q: %v", b.URL, err)
				}
			}
			if b.Accessible {
				fmt.Printf("  [PUBLIC]   %-60s (%s)\n", b.URL, b.Provider)
				publicCount++
			} else {
				fmt.Printf("  [private]  %-60s (%s)\n", b.URL, b.Provider)
				privateCount++
			}
		}
		if len(buckets) == 0 {
			fmt.Println("  No cloud buckets found.")
		}
		fmt.Printf("\nPhase 3 complete: %d public, %d private bucket(s) found.\n",
			publicCount, privateCount)
	}
}

// parsePorts converts a comma-separated port string to a deduplicated slice of
// port numbers in input order. An empty string returns the default port list.
// Non-integer tokens and out-of-range values (< 1 or > 65535) produce a
// descriptive error. Duplicate port numbers are silently dropped — scanning the
// same port twice on the same host produces redundant output without any benefit.
func parsePorts(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return defaultPorts, nil
	}
	parts := strings.Split(s, ",")
	seen := make(map[int]struct{}, len(parts))
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %v", p, err)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("port %d out of range (1–65535)", n)
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		ports = append(ports, n)
	}
	return ports, nil
}

// filterByIP returns the subset of ports that belong to a specific IP address.
// Used to group scan results per IP when an asset resolves to multiple addresses.
func filterByIP(ports []models.Port, ip string) []models.Port {
	var result []models.Port
	for _, p := range ports {
		if p.IP == ip {
			result = append(result, p)
		}
	}
	return result
}
