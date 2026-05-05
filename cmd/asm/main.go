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
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/arvin-sudo/asm-engine/internal/pipeline"
	"github.com/arvin-sudo/asm-engine/internal/web"
	"github.com/arvin-sudo/asm-engine/pkg/models"
)


// main is the CLI entry point. It pre-scans os.Args for --ui before
// delegating to run so that the FlagSet in run() never sees an unknown flag.
// run() creates its own FlagSet and would error on --ui; adding --ui there
// would require making --target optional for that mode, breaking the
// TestRun_MissingTarget assertion.
func main() {
	log.SetFlags(0)

	for _, a := range os.Args[1:] {
		if a == "--ui" || a == "-ui" {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			fmt.Println("DASM by Arv — UI server on http://localhost:8080")
			if err := web.Serve(ctx, ":8080"); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal(err)
			}
			return
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Stdout, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// run is the full scan pipeline. All output is written to w, which lets tests
// capture and inspect output without capturing os.Stdout globally. Fatal
// configuration errors are returned; non-fatal pipeline errors (e.g. a single
// failed store write) are logged to stderr via log.Printf so they do not
// interrupt the scan.
//
// ctx is propagated into the pipeline so that SIGINT (from main) or test
// cancellation stops the scan goroutine cleanly rather than leaving it running
// until natural completion.
func run(ctx context.Context, w io.Writer, args []string) error {
	fs := flag.NewFlagSet("asm-engine", flag.ContinueOnError)
	// Usage and flag-parse errors go to stderr; scan output goes to w.
	fs.SetOutput(os.Stderr)

	target := fs.String("target", "", "target domain to scan (required). Example: --target example.com")
	portsFlag := fs.String("ports", "", "comma-separated TCP ports to scan. Default: 21 common ports.")
	workersFlag := fs.Int("workers", 100, "number of concurrent goroutines for port scanning")
	timeoutFlag := fs.Duration("scan-timeout", 2*time.Second, "per-connection timeout for port scanning and fingerprinting")
	rateLimitFlag := fs.Int("rate-limit", 0, "max TCP connection attempts per second across the worker pool (0 = unlimited). Use to stay below IDS/firewall thresholds.")
	dbFlag := fs.String("db", "", "PostgreSQL DSN for persistence, e.g. postgres://user:pass@localhost/asmdb?sslmode=disable. Omit to disable persistence.")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

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
		return fmt.Errorf("--target is required. Example: asm-engine --target example.com")
	}

	ports, err := parsePorts(*portsFlag)
	if err != nil {
		return fmt.Errorf("--ports: %w", err)
	}

	cfg := pipeline.Config{
		Domain:      domain,
		Ports:       ports,
		Workers:     *workersFlag,
		ScanTimeout: *timeoutFlag,
		RateLimit:   *rateLimitFlag,
		DSN:         *dbFlag,
		IsLocal:     pipeline.IsLocalTarget(domain),
	}

	runner, err := pipeline.NewRunner(cfg)
	if err != nil {
		return err
	}
	defer runner.Close()

	return consumeForCLI(w, runner.Run(ctx, cfg))
}

// consumeForCLI reads events from the pipeline channel and writes the same
// formatted text output that main.go previously produced directly with
// fmt.Fprintf. The output is line-for-line identical to the pre-refactor
// behaviour, which means all CLI-based integration tests continue to pass.
func consumeForCLI(w io.Writer, events <-chan pipeline.ScanEvent) error {
	for e := range events {
		switch e.Type {

		case pipeline.EventPhaseStart:
			var p pipeline.PhasePayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				continue
			}
			fmt.Fprintln(w, p.Message)

		case pipeline.EventPhaseComplete:
			var p pipeline.PhasePayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				continue
			}
			fmt.Fprintln(w, p.Message)

		case pipeline.EventSubdomain:
			var p pipeline.SubdomainPayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				continue
			}
			switch p.Status {
			case "live":
				fmt.Fprintf(w, "  [live]      %-40s %s\n", p.Name, strings.Join(p.IPs, ", "))
			case "dead":
				fmt.Fprintf(w, "  [dead]      %s\n", p.Name)
			case "wildcard":
				fmt.Fprintf(w, "  [wildcard]  %s\n", p.Name)
			case "ptr_live":
				fmt.Fprintf(w, "  [ptr-live]      %-40s %s\n", p.Name, strings.Join(p.IPs, ", "))
			case "ptr_dead":
				fmt.Fprintf(w, "  [ptr-dead]      %s\n", p.Name)
			case "ptr_wildcard":
				fmt.Fprintf(w, "  [ptr-wildcard]  %s\n", p.Name)
			}

		case pipeline.EventDNSIndicator:
			var p pipeline.DNSIndicatorPayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				continue
			}
			fmt.Fprintf(w, "  [%s] %-22s  %s\n", p.Record, p.Service, p.Evidence)

		case pipeline.EventPort:
			var p pipeline.PortPayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				continue
			}
			if p.ServiceName == "" {
				fmt.Fprintf(w, "      %d/tcp   open\n", p.Port)
				continue
			}
			if p.ServiceVersion != "" {
				fmt.Fprintf(w, "      %d/tcp   %-14s %s\n", p.Port, p.ServiceName, p.ServiceVersion)
			} else {
				fmt.Fprintf(w, "      %d/tcp   %s\n", p.Port, p.ServiceName)
			}
			for _, v := range p.Vulnerabilities {
				if v.CVE != "" {
					fmt.Fprintf(w, "               [%s %s: %s]\n", v.Severity, v.CVE, v.Description)
				} else {
					fmt.Fprintf(w, "               [%s: %s]\n", v.Severity, v.Description)
				}
			}
			if len(p.Technologies) > 0 {
				var names []string
				for _, t := range p.Technologies {
					if t.Category != "" {
						names = append(names, t.Name+" ("+t.Category+")")
					} else {
						names = append(names, t.Name)
					}
				}
				fmt.Fprintf(w, "               Tech: %s\n", strings.Join(names, ", "))
			}

		case pipeline.EventBucket:
			var p pipeline.BucketPayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				continue
			}
			if p.Accessible {
				fmt.Fprintf(w, "  [public]   %-60s (%s)\n", p.URL, p.Provider)
			} else {
				fmt.Fprintf(w, "  [private]  %-60s (%s)\n", p.URL, p.Provider)
			}

		case pipeline.EventDiff:
			var p pipeline.DiffPayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				continue
			}
			switch p.Kind {
			case string(models.ChangeNewAsset):
				fmt.Fprintf(w, "  [%-16s] %s\n", p.Kind, p.Domain)
			case string(models.ChangePortOpened), string(models.ChangePortClosed):
				fmt.Fprintf(w, "  [%-16s] %s:%d/%s on %s\n", p.Kind, p.IP, p.Port, p.Proto, p.Domain)
			case string(models.ChangeVersionChange):
				fmt.Fprintf(w, "  [%-16s] %s %s → %s on %s:%d\n",
					p.Kind, p.ServiceName, p.OldVersion, p.NewVersion, p.IP, p.Port)
			}

		case pipeline.EventError:
			var p pipeline.ErrorPayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				continue
			}
			log.Printf("%s: %s", p.Phase, p.Message)
		}
	}
	return nil
}

// parsePorts converts a comma-separated port string to a deduplicated slice of
// port numbers in input order. An empty string returns the default port list.
// Non-integer tokens and out-of-range values (< 1 or > 65535) produce a
// descriptive error. Duplicate port numbers are silently dropped — scanning the
// same port twice on the same host produces redundant output without any benefit.
func parsePorts(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return pipeline.DefaultPorts, nil
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
