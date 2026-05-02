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

- [x] Phase 1a: CT log subdomain discovery (crt.sh)
- [ ] Phase 1b: DNS resolution of discovered subdomains
- [ ] Phase 2: TCP port scanning + service fingerprinting
- [ ] Phase 3: Cloud bucket hunting (S3, Azure Blob)
- [ ] Phase 4: PostgreSQL persistence with change tracking
- [ ] Phase 5: Go vs Python performance benchmarking

## License

MIT — see [LICENSE](LICENSE).
