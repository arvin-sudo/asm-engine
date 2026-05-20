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


## License

MIT — see [LICENSE](LICENSE).
