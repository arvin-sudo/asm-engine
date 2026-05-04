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

	"github.com/arvin-sudo/asm-engine/internal/analysis"
	"github.com/arvin-sudo/asm-engine/internal/cloudscan"
	"github.com/arvin-sudo/asm-engine/internal/discovery"
	"github.com/arvin-sudo/asm-engine/internal/fingerprint"
	"github.com/arvin-sudo/asm-engine/internal/scanner"
	"github.com/arvin-sudo/asm-engine/internal/storage"
	"github.com/arvin-sudo/asm-engine/internal/vulndb"
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

// webServiceNames is the set of service names for which web technology
// fingerprinting is attempted. This handles the service-name routing path:
// when banner fingerprinting identifies a service as nginx/apache/etc. on a
// non-standard port, this map ensures FingerprintWeb is still called.
//
// Standard-port routing (80, 443, 8080, 8443, 8888) is handled separately by
// WebFingerprinter.CanFingerprint — the fingerprinter owns that knowledge so
// main.go does not need to hardcode port numbers.
var webServiceNames = map[string]bool{
	"http":   true,
	"https":  true,
	"nginx":  true,
	"apache": true,
	"iis":    true,
}

const (
	// ctLogTimeout is the HTTP client deadline for crt.sh CT log queries.
	// crt.sh aggregates hundreds of certificate transparency logs and can take
	// 20–25 seconds for large organisations with extensive certificate histories.
	// 30 seconds provides a comfortable margin without stalling the pipeline.
	ctLogTimeout = 30 * time.Second

	// hackerTargetTimeout is the HTTP client deadline for HackerTarget passive DNS.
	// HackerTarget returns plain text with no server-side aggregation — typical
	// responses arrive in under 2 seconds. 10 seconds is deliberately generous
	// to absorb transient latency spikes without causing false failures.
	hackerTargetTimeout = 10 * time.Second

	// waybackTimeout is the HTTP client deadline for the Wayback Machine CDX API.
	// The CDX index can return up to 10,000 URL records for popular domains.
	// Serialising that payload over a variable-latency connection requires a
	// longer window than the HackerTarget endpoint; 60 seconds prevents premature
	// cutoff on large targets.
	waybackTimeout = 60 * time.Second
)

// main is the CLI entry point.
//
// Full pipeline (Phases 1–4 + advanced analysis):
//
//	flag --target
//	  → MultiSourceDiscoverer.Discover     (Phase 1a: CT logs + HackerTarget + WayBack)
//	  → DNSResolver.Discover               (Phase 1b: resolve each subdomain to live IPs)
//	  → PTREnricher.Enrich                 (Phase 1c: reverse DNS enrichment from live IPs)
//	  → DNSIntelligenceScanner.Scan        (Phase 1d: TXT/MX third-party service indicators)
//	  → store.SaveAsset                    (Phase 4: persist live asset, optional)
//	  → TCPScanner.Scan                    (Phase 2: probes open TCP ports with a worker pool)
//	  → store.SavePort                     (Phase 4: persist each open port)
//	  → BannerFingerprinter.Fingerprint    (Phase 2: reads service banners / HTTP headers)
//	  → VulnDB.Check                       (Vuln mapping: annotate with known CVEs)
//	  → WebStackFingerprinter.FingerprintWeb (Web tech: detect CMS/frameworks on HTTP ports)
//	  → store.SaveService                  (Phase 4: persist service when name or banner is present)
//	  → Differ.DiffAssets / DiffAsset      (Diff: compare against previous scan if DB enabled)
//	  → BucketHunter.Scan                  (Phase 3: probes cloud storage URL patterns)
//	  → store.SaveBucket                   (Phase 4: persist bucket findings)
//	  → stdout
//
// All store calls are guarded by a nil check — when --db is absent the
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
	// Phase 1a — passive recon via multiple OSINT sources.
	// -------------------------------------------------------------------------
	// MultiSourceDiscoverer fans out to three complementary sources:
	//   • CTDiscoverer    — Certificate Transparency logs (crt.sh): finds every
	//     subdomain that has ever had a public TLS certificate.
	//   • HackerTargetDiscoverer — passive DNS dataset: finds subdomains that
	//     never had TLS certificates (plain HTTP, internal-only).
	//   • WayBackDiscoverer — Wayback Machine CDX API: finds historical hostnames
	//     that no longer have active certificates but may still have live DNS.
	// Results are merged and deduplicated; the first source that reports a
	// hostname wins the Source tag for coverage analysis in Phase 5.
	var subdiscoverer discovery.SubdomainDiscoverer = discovery.NewMultiSourceDiscoverer(
		discovery.NewCTDiscoverer(&http.Client{Timeout: ctLogTimeout}),
		discovery.NewHackerTargetDiscoverer(&http.Client{Timeout: hackerTargetTimeout}),
		discovery.NewWayBackDiscoverer(&http.Client{Timeout: waybackTimeout}),
	)

	fmt.Printf("Phase 1a: passive recon for %s (CT logs, HackerTarget, WayBack)...\n\n", domain)

	subdomains, err := subdiscoverer.Discover(domain)
	if err != nil {
		log.Fatalf("subdomain discovery failed: %v", err)
	}

	fmt.Printf("Found %d subdomains.\n\n", len(subdomains))

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
	fmt.Printf("\nPhase 1b complete: %d live, %d wildcard, %d dead — %d total subdomains discovered.\n",
		len(liveAssets), wildcardCount, deadCount, len(subdomains))

	// -------------------------------------------------------------------------
	// Phase 1c — PTR reverse DNS enrichment.
	// -------------------------------------------------------------------------
	// After Phase 1b has built the live-asset list, query the PTR records for
	// every discovered IP. PTR records reveal sibling services on the same cloud
	// infrastructure — services that never had public TLS certificates (invisible
	// to CT logs) and were never indexed by HackerTarget or WayBack.
	if len(liveAssets) > 0 {
		fmt.Printf("\nPhase 1c: PTR enrichment on discovered IPs...\n\n")

		// Collect every unique IP from all live assets.
		var allIPs []string
		for _, a := range liveAssets {
			allIPs = append(allIPs, a.IPs...)
		}

		// Build a set of already-known domain names to avoid resolving
		// PTR hostnames that are already in the live-asset list.
		knownDomains := make(map[string]struct{}, len(liveAssets))
		for _, a := range liveAssets {
			knownDomains[a.Domain] = struct{}{}
		}

		ptrEnricher := discovery.NewPTREnricher(discovery.NewNetPTRResolver())
		ptrSubs := ptrEnricher.Enrich(allIPs)

		ptrNew := 0
		for _, s := range ptrSubs {
			if _, ok := knownDomains[s.Name]; ok {
				continue
			}
			if s.IsWildcard() {
				fmt.Printf("  [ptr-wildcard]  %s\n", s.Name)
				continue
			}
			asset, err := resolver.Discover(s.Name)
			if err != nil {
				fmt.Printf("  [ptr-dead]      %s\n", s.Name)
				continue
			}
			fmt.Printf("  [ptr-live]      %-40s %s\n", asset.Domain, strings.Join(asset.IPs, ", "))
			liveAssets = append(liveAssets, asset)
			knownDomains[asset.Domain] = struct{}{}
			ptrNew++
			if store != nil {
				if err := store.SaveAsset(asset); err != nil {
					log.Printf("store: save asset %q: %v", asset.Domain, err)
				}
			}
		}
		fmt.Printf("\nPhase 1c complete: %d new asset(s) discovered via PTR.\n", ptrNew)
	} else {
		fmt.Printf("\nPhase 1c: skipped — no live assets to enrich.\n")
	}

	// -------------------------------------------------------------------------
	// Phase 1d — DNS intelligence (TXT/MX service indicators).
	// -------------------------------------------------------------------------
	// Query the target domain's TXT and MX records to identify third-party
	// service integrations. These records reveal the indirect attack surface:
	// SPF includes expose authorised email relays (Mailgun, SendGrid, SES) and
	// MX records identify the email provider — both are shadow IT indicators
	// that no amount of subdomain enumeration would otherwise surface.
	fmt.Printf("\nPhase 1d: DNS intelligence for %s...\n\n", domain)

	intelScanner := discovery.NewDNSIntelligenceScanner(discovery.NewNetDNSIntelResolver())
	indicators, err := intelScanner.Scan(domain)
	if err != nil {
		log.Printf("dns intel scan: %v", err)
	}

	if len(indicators) == 0 {
		fmt.Println("  No third-party service indicators found.")
	} else {
		for _, ind := range indicators {
			fmt.Printf("  [%s] %-22s  %s\n", ind.Record, ind.Service, ind.Evidence)
		}
	}
	fmt.Printf("\nPhase 1d complete: %d service indicator(s) found.\n", len(indicators))

	// -------------------------------------------------------------------------
	// Phase 2 — TCP port scanning + service fingerprinting.
	// -------------------------------------------------------------------------
	// Guarded: bucket hunting (Phase 3) is domain-based and runs regardless of
	// whether any live assets were found. Port scanning requires a live IP, so
	// it is skipped when the asset list is empty.
	if len(liveAssets) > 0 {
		// Declared as the Scanner and Fingerprinter interfaces so that tests
		// can inject in-memory doubles without changing this file.
		fmt.Printf("\nPhase 2: scanning %d port(s) on %d live asset(s) — %d workers, %v timeout...\n\n",
			len(ports), len(liveAssets), *workersFlag, *timeoutFlag)

		var tcpScanner scanner.Scanner = scanner.NewTCPScanner(ports, *timeoutFlag, *workersFlag)

		// Give fingerprinting one extra second beyond the scan timeout. The scan
		// timeout only needs to confirm a port is open (one RTT). Fingerprinting
		// requires a full request-response cycle, so a slightly longer window
		// avoids false "no banner" results on services with high initial latency.
		var bannerFP fingerprint.Fingerprinter = fingerprint.NewBannerFingerprinter(
			*timeoutFlag+time.Second, 4096,
		)

		// WebStackFingerprinter runs after banner fingerprinting for HTTP/HTTPS
		// ports. It issues a full GET with the correct Host header so that
		// virtual-hosting servers return the intended site, enabling detection
		// of CMSes and frameworks hidden behind a CDN or reverse proxy.
		var webFP fingerprint.WebFingerprinter = fingerprint.NewWebStackFingerprinter(
			*timeoutFlag + time.Second,
		)

		// VulnDB is wired as VulnerabilityChecker so tests can substitute a
		// stub without touching the built-in CVE dataset.
		var vulnChecker vulndb.VulnerabilityChecker = vulndb.New()

		// Differ computes asset and port/version deltas relative to the last
		// scan stored in the database. Only instantiated when persistence is
		// active — without a DB there is no history to compare against.
		var differ *analysis.Differ
		if store != nil {
			differ = analysis.NewDiffer(store)
		}

		// Snapshot the list of known assets BEFORE saving new ones.
		// DiffAssets needs the pre-scan state to identify newly discovered domains.
		var assetDiff *models.ScanDiff
		if differ != nil {
			assetDiff, err = differ.DiffAssets(liveAssets)
			if err != nil {
				log.Printf("diff: assets: %v", err)
			}
		}

		totalOpen := 0
		// allDiffs accumulates per-asset port/service diffs for the summary
		// printed after all Phase 2 output.
		var allDiffs []*models.ScanDiff

		for _, asset := range liveAssets {
			openPorts, err := tcpScanner.Scan(asset)
			if err != nil {
				fmt.Printf("  [scan error] %s: %v\n\n", asset.Domain, err)
				continue
			}

			// Load the pre-scan DB snapshot BEFORE any writes for this asset.
			// DiffAsset compares against this snapshot, so it must reflect the
			// state from the previous scan run — not the rows we are about to
			// write. Loading after SavePort or SaveService would cause the diff
			// to compare new vs new, silently dropping all version-change events.
			var history *models.AssetHistory
			if differ != nil {
				h, histErr := differ.LoadAssetHistory(asset.Domain)
				if histErr != nil {
					log.Printf("diff: load history %q: %v", asset.Domain, histErr)
				} else {
					history = h
				}
			}

			if len(openPorts) == 0 {
				fmt.Printf("  %s — no open ports found\n\n", asset.Domain)
				// Still run the diff: if the previous scan recorded open ports
				// and now none are found, those ports must be reported as closed.
				if differ != nil && history != nil {
					diff := differ.DiffAsset(asset.Domain, history, nil, nil)
					if !diff.IsEmpty() {
						allDiffs = append(allDiffs, diff)
					}
				}
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
			var scannedServices []models.Service
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

					svc, err := bannerFP.Fingerprint(p)
					if err != nil {
						// Dial or write failed — port is open but nothing to save or show.
						fmt.Printf("      %d/tcp   open\n", p.Number)
						continue
					}

					// Annotate the service with matching CVEs before saving or
					// printing. The result is stored on the struct so the
					// complete service picture (identity + known CVEs) travels
					// together through the pipeline. Vulnerabilities are never
					// persisted — they are recomputed from the built-in dataset
					// on every run, so stored vulns would only go stale.
					svc.Vulnerabilities = vulnChecker.Check(svc.Name, svc.Version)

					// Persist whenever there is something meaningful to store.
					// A service with no recognised name may still carry a raw banner
					// worth preserving for manual analysis — the Fingerprinter contract
					// guarantees Banner holds whatever bytes arrived, regardless of
					// whether automated classification succeeded. Only skip saving when
					// both Name and Banner are empty (the service sent nothing at all).
					if store != nil && (svc.Name != "" || svc.Banner != "") {
						if err := store.SaveService(asset.Domain, svc); err != nil {
							log.Printf("store: save service %s:%d: %v", svc.Port.IP, svc.Port.Number, err)
						}
					}
					if svc.Name != "" || svc.Banner != "" {
						scannedServices = append(scannedServices, svc)
					}

					if svc.Name == "" {
						// Port is open and reachable but the service did not produce
						// enough information to identify it.
						fmt.Printf("      %d/tcp   open\n", p.Number)
						continue
					}
					if svc.Version != "" {
						fmt.Printf("      %d/tcp   %-14s %s\n", p.Number, svc.Name, svc.Version)
					} else {
						fmt.Printf("      %d/tcp   %s\n", p.Number, svc.Name)
					}

					// Print CVEs from the annotated service struct — no second
					// Check call needed; the results are already on svc.
					for _, v := range svc.Vulnerabilities {
						if v.CVE != "" {
							fmt.Printf("               [%s %s: %s]\n",
								v.Severity, v.CVE, v.Description)
						} else {
							fmt.Printf("               [%s: %s]\n",
								v.Severity, v.Description)
						}
					}

					// Technology stack fingerprinting: run a full GET on HTTP/HTTPS
					// ports to detect CMSes, frameworks, and languages that the
					// Server header does not expose.
					if webServiceNames[svc.Name] || webFP.CanFingerprint(p.Number) {
						techs, err := webFP.FingerprintWeb(asset.Domain, p)
						if err == nil && len(techs) > 0 {
							var techNames []string
							for _, tech := range techs {
								if tech.Category != "" {
									techNames = append(techNames, tech.Name+" ("+tech.Category+")")
								} else {
									techNames = append(techNames, tech.Name)
								}
							}
							fmt.Printf("               Tech: %s\n", strings.Join(techNames, ", "))
						}
					}
				}
			}
			fmt.Println()

			// Compute port and service diffs in a single call using the
			// pre-scan snapshot. Both ports and services are compared here
			// rather than in two separate calls — this is what makes service
			// version detection correct: history was read before SaveService
			// ran, so hist.Version holds the previous scan's value.
			if differ != nil && history != nil {
				diff := differ.DiffAsset(asset.Domain, history, openPorts, scannedServices)
				if !diff.IsEmpty() {
					allDiffs = append(allDiffs, diff)
				}
			}
		}

		fmt.Printf("Phase 2 complete: %d open port(s) across %d live asset(s).\n",
			totalOpen, len(liveAssets))

		// -------------------------------------------------------------------------
		// Differential Analysis summary.
		// -------------------------------------------------------------------------
		// Printed after Phase 2 so all scan results appear first. Only shown when
		// persistence is enabled — without a DB there is no historical state.
		if differ != nil {
			fmt.Printf("\n--- Differential Analysis ---\n")
			anyChange := false

			// New assets discovered since last scan.
			if assetDiff != nil {
				for _, c := range assetDiff.AssetChanges {
					fmt.Printf("  [%-16s] %s\n", c.Kind, c.Domain)
					anyChange = true
				}
			}

			// Per-asset port and version changes.
			for _, d := range allDiffs {
				for _, pc := range d.PortChanges {
					fmt.Printf("  [%-16s] %s:%d/%s on %s\n",
						pc.Kind, pc.Port.IP, pc.Port.Number, pc.Port.Proto, d.Domain)
					anyChange = true
				}
				for _, sc := range d.ServiceChanges {
					fmt.Printf("  [%-16s] %s %s → %s on %s:%d\n",
						models.ChangeVersionChange, sc.ServiceName,
						sc.OldVersion, sc.NewVersion,
						sc.Port.IP, sc.Port.Number)
					anyChange = true
				}
			}

			if !anyChange {
				fmt.Printf("  (no changes detected since last scan)\n")
			}
		}
	} else {
		fmt.Printf("\nPhase 2: skipped — no live assets to scan.\n")
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
	fmt.Printf("\nPhase 3: cloud bucket scan for %s...\n\n", domain)

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
