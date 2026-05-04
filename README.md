# asm-engine

A high-performance Attack Surface Management engine in Go.
Discovers subdomains, open ports, and exposed services using public OSINT data.

Bachelor Thesis — Nordic Defender × Chalmers University of Technology.

## Prerequisites

- Go 1.25+
- Docker (for integration tests and benchmarking)

## Quick Start

```bash
make build
make run TARGET=example.com
make test

# With PostgreSQL persistence and custom scan options:
# asm-engine --target example.com --ports 80,443,8080 --workers 50 --scan-timeout 3s \
#   --db "postgres://user:pass@localhost/asmdb?sslmode=disable"
#
# Throttle connection rate to avoid triggering IDS/firewall rules:
# asm-engine --target example.com --rate-limit 20
```

## Architecture

```
/cmd        — CLI entry points (thin wiring, no business logic)
/internal   — core modules: discovery, scanning, fingerprinting, storage
/pkg        — shared models used across all modules
```

Each internal module depends only on `/pkg/models` and its own interfaces.
A change in one module never breaks another.

## Roadmap

- [x] Phase 1a: CT log subdomain discovery (crt.sh, HackerTarget, WayBack Machine) — concurrent fan-out
- [x] Phase 1b: DNS resolution of discovered subdomains
- [x] Phase 1c: PTR reverse DNS enrichment from live IPs
- [x] Phase 1d: DNS intelligence — TXT/MX third-party service indicators (SPF, email providers)
- [x] Phase 2: TCP port scanning + service fingerprinting (goroutine worker pool)
- [x] Phase 3: Cloud bucket hunting (AWS S3, Azure Blob, GCP Cloud Storage)
- [x] Phase 4: PostgreSQL persistence with FirstSeen/LastSeen change tracking
- [x] Differential analysis — detect new assets, opened/closed ports, version changes across scans
- [x] Vulnerability mapping — built-in CVE dataset, zero-latency local check
- [x] Technology stack fingerprinting — CMS/framework detection on HTTP/HTTPS ports
- [ ] Phase 5: Go vs Python performance benchmarking

## License

MIT — see [LICENSE](LICENSE).
