# ASM Engine — Implementation Notes

**Project:** Automated External Attack Surface Management (ASM)  
**Author:** Arvin Allahbakhsh  
**Institution:** Chalmers University of Technology  
**Company:** Nordic Defender  

---

## Overview

This document describes the technical implementation of the ASM engine, covering every architectural decision made during development — with particular emphasis on **why** each decision was made, not just what was built. It is intended to support the thesis write-up and to provide enough context for anyone reading the source code for the first time.

The engine is written in Go and is structured as a four-stage pipeline:

```
CT Log Discovery → DNS Resolution → TCP Port Scanning → Service Fingerprinting
     (Phase 1a)       (Phase 1b)          (Phase 2a)           (Phase 2b)
```

Each stage is isolated behind an interface. No stage knows how the previous one was implemented or how the next one will use its output. This is what makes the pipeline extensible: Phase 3 (cloud bucket hunting) and Phase 4 (PostgreSQL persistence) can be attached to the pipeline without modifying any existing code.

---

## What is ASM
asm, or attack surface management is one of the biggest defensive aresenals in cybersecurity. but what is it and why should you be considering it? What is an attack surface?: an organizations attack surface is the sum total of all potential routes an attacker could attempt to use as a point of initial entry. for example, an attack surface could be comprised of a log-in web form an attacker could attempt to brute force, a misconfigured cloud bucket thats open to public access, an unpatched java application running on a dusty server you though was decommissioned years ago, and even systems in your partner supply chain, like an invoicing and accounting system that has access to your network. these plus every other potential point of entry exposed to an attacker, go into forming the total attack surface of an organization. and in simplistic terms, shrking the size of that attack surface reduces and organizations vulnerability to attack. and the smaller the target, the easier it is to protect. organizations attack surfaces vary massievely, from small businesses that have very little digital infrastructure, all the way to global energy and telecommunications companies with thousands, if not millions, of IoT devices and sensors monitoring every aspect of their supply chain. now that attack surface is established, what is it that attack surface management does? if we look at how an attacker would understand an organizations attack surface, typically theyd use an open source tool like Kali Linux to go away and crawl a companys online presence. or in other words, use a computer to try the handle on every possible door, one by one, until they find all of them. once that attack surface has been mapped, typically the would then attempt to understand more about what software is running that may be out of date and vulnerable to known attacks that they could then use to try and force the foor open and gain entry to your organization. if we now look at how an cyber security defender team works, how can we use this knowledge to better defend ourselves? many busineses are deploying attack surface management solutions to help them take an outside-in view on their security posture. asm solutions scan your digital presence much like an attacker would, often exposing those shadow IT resources, like cloud services without an owner, and old servers running unpatched software. its mostly about awareness. there will always be vulnerabilities and zero-day attacks that a business need to address, but they're only able to do that on the subsection of the IT estate that they're actively tracking and aware of. through robust vulnerability management practices, businesses should always ssek to minimize the number of systems they know about which are exposed to attack, this "known and exposed" section in the middle of to the left "unknown and exposed" and to the right "known and unexposed". by giving businesses and outside-in view on their attack surface, ASM helps move items from the most risky "unknown and exposed" category over to the "known and exposed" category, and then prioritize in what order to move those over to the "known and unexposed" category. in other words, it helps them take the fastest path to reduce their risk by discovering unknown assets, then patching the systems which are at most risk first. the best asm systems are able to deliver this entirely from the cloud without any software to deploy, and build an ethos of cyclical and ongoing improvements in to the workflow, much like sparring with an attacker or playing cat and mouse, to improve and validate defenses on an iterative basis. this is typically a four step process: firstly discovering unknown attack surfaces. secondly, gaining insight and a deep understanding of them, finding out what that tool is actually doing. thirdly, prioritizing which of these targets are most tempting to attackers and iteratively improving the risk posture. 4th and finally, testing to validate the effectiveness of your actions. throughout this, asm is continously providing businesses an attackers point of view. it should help business to understand which are their most tempting targets. 


## Repository Layout

```
asm-engine/
├── cmd/asm/
│   ├── main.go                      CLI entry point — wiring only, no logic
│   └── main_test.go                 parsePorts + filterByIP unit tests
├── internal/
│   ├── discovery/
│   │   ├── discoverer.go            SubdomainDiscoverer + Discoverer interfaces
│   │   ├── http_client.go           HTTPClient interface
│   │   ├── resolver.go              Resolver + PTRResolver interfaces + net adapters
│   │   ├── ct_discoverer.go         Phase 1a: queries crt.sh CT logs
│   │   ├── hackertarget_discoverer.go  Phase 1a: queries HackerTarget passive DNS
│   │   ├── wayback_discoverer.go    Phase 1a: queries Wayback Machine CDX API
│   │   ├── multi_source_discoverer.go  Phase 1a: fans out to all three sources
│   │   ├── dns_resolver.go          Phase 1b: resolves hostnames to live IPs
│   │   ├── ptr_enricher.go          Phase 1c: reverse DNS enrichment from IPs
│   │   └── dns_intel.go             Phase 1d: TXT/MX third-party service indicators
│   ├── scanner/
│   │   ├── scanner.go               Scanner interface
│   │   └── tcp_scanner.go           Phase 2a: worker-pool TCP port prober
│   ├── fingerprint/
│   │   ├── fingerprinter.go         Fingerprinter + WebFingerprinter interfaces
│   │   ├── banner_fingerprinter.go  Phase 2b: banner/HTTP service identification
│   │   └── web_stack_fingerprinter.go  Phase 2b: HTTP GET + header/body tech detection
│   ├── cloudscan/
│   │   ├── cloudscan.go             HeadClient + CloudScanner interfaces
│   │   └── bucket_hunter.go         Phase 3: cloud storage bucket discovery
│   ├── storage/
│   │   ├── store.go                 Store interface
│   │   └── postgres_store.go        Phase 4: PostgreSQL persistence implementation
│   ├── analysis/
│   │   └── differ.go                Differential analyser: DiffAssets + DiffAsset
│   └── vulndb/
│       └── vulndb.go                VulnerabilityChecker interface + built-in CVE dataset
└── pkg/models/
    ├── asset.go                     Shared data types: Subdomain, Asset, Port, Service,
    │                                BucketResult, AssetRecord, ServiceIndicator, Technology
    ├── diff.go                      Differential analysis types: ScanDiff, AssetHistory,
    │                                ChangeKind, AssetChange, PortChange, ServiceChange
    └── vulnerability.go             Vulnerability severity model: Severity, Vulnerability
```

The `/pkg/models` package is the only package every other package is allowed to import. The `/internal` packages depend only on `/pkg/models` and on each other's interfaces, never on concrete types from sibling packages. `/cmd` is the only place where concrete types are instantiated and wired together. This layering is the structural guarantee that the pipeline stages remain independent.

---

## Core Data Model (`pkg/models`)

Four types flow through the pipeline, each representing a different level of confidence and enrichment.

### `Subdomain`

```go
type Subdomain struct {
    Name   string
    Source string
}
```

A hostname discovered by passive recon. At this stage we know the name exists (it appeared in a CT log) but we have not verified whether the host is live or what IP addresses it resolves to. Keeping this separate from `Asset` enforces the distinction between raw intelligence and verified fact — collapsing them would make it impossible to tell which data had been confirmed and which had not.

The `Source` field records which technique found the hostname (e.g. `"ct_log"`). This is forward-looking: Phase 5 benchmarks the output of different discovery sources. Having the source embedded in every record means the analysis query is just a group-by rather than a join.

`IsWildcard()` checks for the `*.` prefix. Wildcards need their own code path because they prove a wildcard TLS certificate was issued — real intelligence — but they are not valid DNS hostnames and cannot be passed to the resolver. Without this method, they would generate spurious NXDOMAIN errors and be misclassified as dead hosts.

### `Asset`

```go
type Asset struct {
    Domain string
    IPs    []string
}
```

A confirmed, live host: a hostname plus all IP addresses it currently resolves to. `IPs` is a slice, not a single string, because a hostname behind a load balancer or CDN resolves to multiple addresses. Each IP is an independently reachable point on the attack surface. Storing only the first IP would be a silent data loss.

`Asset` is the input to Phase 2. The port scanner receives the full struct — with all IPs — rather than just a single IP string, because different IPs for the same domain can run different software. Accepting the full `Asset` lets the scanner probe all of them without the caller needing to know how.

### `Port`

```go
type Port struct {
    IP     string
    Number int
    Proto  string
}
```

A single open port on a specific IP address. The `IP` field is essential: without it, two ports with the same number on different IPs of the same asset would be indistinguishable. `Proto` is always `"tcp"` in Phase 2 but the field is there for UDP support in a future phase.

### `Service`

```go
type Service struct {
    Port    Port
    Name    string
    Version string
    Banner  string
}
```

The enriched output of fingerprinting. `Name` and `Version` are what transform a raw open port into an actionable finding: `"port 443 open"` is noise, `"nginx/1.18.0 — EOL version, known CVEs"` is something a client can act on. `Banner` stores the raw bytes received from the service so that analysts can apply custom detection signatures after the fact without re-scanning.

When fingerprinting is inconclusive, `Name` and `Version` are empty strings and `Banner` holds whatever was received. This is intentional: ambiguity is not a failure. Returning an error for an unidentified service would hide the finding from the output entirely.

---

## Phase 1a — CT Log Discovery (`internal/discovery`)

### Why Certificate Transparency logs?

Every trusted Certificate Authority is required by the CA/Browser Forum to publish issued certificates to public CT logs within 24 hours. This means any subdomain that has ever had a public TLS certificate — including forgotten staging servers, decommissioned APIs, and shadow IT — will appear in a CT log. The organisation itself may not remember these subdomains exist.

crt.sh aggregates hundreds of CT logs and provides a free, unauthenticated API. A single query for `%.example.com` returns every subdomain certificate ever issued for that domain. This gives an attacker's-eye view of the target's historical footprint with no contact with the target at all.

### Interface design

```go
type SubdomainDiscoverer interface {
    Discover(domain string) ([]models.Subdomain, error)
}
```

The interface is narrow: one method, one responsibility. `CTDiscoverer` satisfies it. A future DNS brute-force module would satisfy it too, with no changes to the interface or to any consumer. This is the Open/Closed principle applied concretely: adding a new discovery source means creating a new struct, not modifying existing ones.

### Implementation decisions

**Streaming JSON decode.** crt.sh returns one JSON array containing every certificate entry. For popular domains this can be thousands of records. The implementation uses `json.NewDecoder(resp.Body).Decode(&entries)` rather than reading the entire body into memory first and then unmarshalling. Streaming keeps peak memory usage flat regardless of response size — relevant when scanning organisations with large certificate histories.

**SAN splitting.** A TLS certificate can secure many domains via Subject Alternative Names. crt.sh packs all the SANs for one certificate into a single `name_value` string, joined by `\n`. If we stored the raw field without splitting, `"*.example.com\nexample.com"` would become one malformed hostname entry instead of two valid, independently actionable ones.

**Deduplication.** The same hostname frequently appears across dozens of certificates — annual renewals, wildcard certs, multi-domain certs. The implementation uses a `map[string]struct{}` as a set to deduplicate before returning results. Without this, the DNS resolver in Phase 1b would make redundant network calls for the same host, multiplying latency unnecessarily.

**Lowercase normalisation.** DNS names are case-insensitive (RFC 4343). `"API.example.com"` and `"api.example.com"` are the same host. Without normalisation, the deduplication map treats them as distinct — the resolver makes redundant calls and the output lists the same host twice with different capitalisation.

**Injected HTTP client.** `CTDiscoverer` accepts an `HTTPClient` interface at construction time rather than creating its own `*http.Client`. This is Dependency Injection: the production binary passes `&http.Client{Timeout: 30*time.Second}`, and tests pass a mock that returns predetermined responses. Neither changes the struct's code.

```go
type HTTPClient interface {
    Get(url string) (*http.Response, error)
}
```

The interface defines only the method `CTDiscoverer` actually calls. `*http.Client` satisfies it with no adapter needed, because its method signature matches exactly.

---

## Phase 1b — DNS Resolution (`internal/discovery`)

### What this stage does

Phase 1b takes the unverified hostnames from Phase 1a and confirms which ones are currently live by performing A and AAAA lookups. A host that resolves successfully becomes an `Asset` (with its IP addresses) ready for port scanning. A host that returns NXDOMAIN is reported as dead.

Dead hosts are worth reporting, not silently discarding. A subdomain that no longer resolves may still have stale DNS entries elsewhere, forgotten firewall rules, or dangling cloud resources — all real security concerns.

### Interface design

```go
type Discoverer interface {
    Discover(domain string) (models.Asset, error)
}
```

`DNSResolver` satisfies this interface. `CTDiscoverer` satisfies `SubdomainDiscoverer`. Two different interfaces for two different contracts. They were kept separate because:

1. Their input types differ (`string` returning `[]Subdomain` vs. `string` returning `Asset`).
2. Their failure semantics differ (CT failure means the data source is down; DNS failure means the host is dead — a normal, meaningful outcome).
3. Their concurrency futures differ: the CT query is one HTTP call; the DNS resolution loop is the natural point where parallelism would pay off if the subdomain list is large.

### The `Resolver` interface

```go
type Resolver interface {
    LookupHost(host string) ([]string, error)
}
```

`DNSResolver` depends on this interface rather than directly on `net.LookupHost`. This makes `DNSResolver` testable without a live DNS server: tests inject a `mockResolver` that returns controlled responses. The production path uses `netResolver`, which wraps `net.LookupHost`.

Why not depend on `net.Resolver` directly? `net.Resolver.LookupHost` requires a `context.Context`. Accepting it would force every caller and every test to construct and manage a context before we have any measured reason to need cancellation. The narrow interface defers that decision to the day a timeout problem is actually observed.

---

## Phase 2a — TCP Port Scanning (`internal/scanner`)

### The performance problem this phase solves

Sequential port scanning is the canonical example of where Go's concurrency model delivers measurable value. Consider a realistic scan:

- 50 live assets discovered in Phase 1b
- 21 ports in the default list
- 2-second connection timeout per port

**Sequential worst case:** `50 assets × 21 ports × 2 s = 35 minutes`

This worst case is not exotic — it occurs whenever a firewall silently drops packets (a "filtered" port) rather than sending a TCP RST. The dialer holds the connection open for the full timeout before giving up, so every filtered port costs the maximum possible time.

**With 100 concurrent workers:** the same 1 050 probes complete in approximately **2 seconds total** — the timeout of the last batch — because all probes run in parallel.

This is the performance story the thesis is built around: Go's goroutines make a problem that takes 35 minutes sequentially solvable in 2 seconds with a 12-line worker pool. Python would require `asyncio` or `ThreadPoolExecutor` to achieve the same effect; Go's built-in goroutines and channels make it the natural language choice for this workload.

### Interface design

```go
type Scanner interface {
    Scan(asset models.Asset) ([]models.Port, error)
}
```

`Scan` accepts a full `Asset` rather than a single IP string. An asset can resolve to multiple IP addresses — each is an independent point on the attack surface. Accepting the full struct lets each implementation decide how to handle multiple IPs: probe all of them (the current behaviour), probe only the first, or probe them in parallel. That decision stays inside the implementation without changing the interface.

### Worker pool design

```go
type TCPScanner struct {
    ports   []int
    timeout time.Duration
    workers int
}
```

The pool is implemented with two buffered channels and a `sync.WaitGroup`:

```
jobs channel ─────────────────────────────────────────────────────►
                │        │        │        │        │
            worker 1  worker 2  worker 3  ...  worker N
                │        │        │        │        │
results channel ◄─────────────────────────────────────────────────
```

**Why a fixed-size pool rather than one goroutine per port?**

The naive approach — `go func() { net.DialTimeout(...) }()` for each probe — is unbounded. An asset with five IP addresses and 1 000 ports would spawn 5 000 goroutines simultaneously. Each goroutine that successfully connects consumes a file descriptor; most operating systems cap processes at around 1 024 open descriptors by default (`ulimit -n`). Exceeding this limit causes dials to fail with "too many open files" — not because the ports are closed, but because the local OS ran out of resources.

A fixed-size pool bounds concurrency to a predictable number regardless of how large the port list grows. The 100-worker default means at most 100 simultaneous TCP connections — safely within standard OS limits and consistent with not triggering rate-limiting on the target network.

**Why buffered channels?**

The jobs channel is pre-allocated with capacity `len(IPs) × len(ports)`. This lets the main goroutine enqueue all jobs without blocking — workers start consuming immediately while new jobs are still being added. If the channel were unbuffered, the main goroutine would block on every send until a worker was ready, serialising what should be parallel dispatch.

**The results-close pattern:**

```go
go func() {
    wg.Wait()
    close(results)
}()

for p := range results {
    open = append(open, p)
}
```

`close(results)` cannot happen in the main goroutine — the main goroutine is blocked draining `results`. It cannot happen inside the workers — any individual worker finishing does not mean all workers are done. It must happen in a third goroutine that waits for the `WaitGroup` to reach zero and then closes the channel. This causes the `for range results` loop to terminate naturally.

**IPv6 correctness:**

All address construction uses `net.JoinHostPort(ip, strconv.Itoa(port))` rather than `fmt.Sprintf("%s:%d", ip, port)`. The difference matters for IPv6: `fmt.Sprintf` produces `"2001:db8::1:80"` — an ambiguous string where the last colon could be part of the address or the port separator. `net.JoinHostPort` produces `"[2001:db8::1]:80"`, which is unambiguous and what the Go dial functions expect.

**What "closed" means:**

A failed dial is not returned as an error. It means the port is closed or filtered — a normal, expected outcome when scanning many ports. Only successful connections produce a `Port` result. The distinction between "refused" (port actively closed, RST sent back) and "timed-out" (port filtered, no response) is invisible to the caller here — both are closed ports from a scan-results perspective.

---

## Phase 2b — Service Fingerprinting (`internal/fingerprint`)

### Why fingerprinting is a separate stage

The scanner and the fingerprinter have fundamentally different connection lifecycles:

- **Scanner:** dial → confirm TCP handshake succeeds → close immediately. No data is read or written. Goal: confirm the port is open. Time per connection: one round-trip.
- **Fingerprinter:** dial → read/write data to identify the service → close. Goal: identify what software is running. Time per connection: one or more round-trips.

Merging these into one struct would mean the scanner would need to know about SSH banners, HTTP headers, and TLS handshakes. That violates Single Responsibility. More practically, it would make it impossible to scan all ports quickly (the scanner's job) and then fingerprint only the ones that are open (the fingerprinter's job).

### Interface design

```go
type Fingerprinter interface {
    Fingerprint(port models.Port) (models.Service, error)
}
```

`Fingerprint` accepts a `Port` struct rather than separate IP, number, and protocol arguments. If we later add fields to `Port` (a timeout hint, a scan timestamp), no fingerprinter caller needs to be updated — the method signature is stable.

### Protocol routing

Not all services use the same protocol on first connection. The fingerprinter routes to one of three strategies based on the port number:

```
Port 443, 8443   →  TLS dial + HTTP HEAD request
Port 80, 8080, 8888  →  plain dial + HTTP HEAD request
All others       →  read the first N bytes on connect
```

**Why HTTP HEAD and not GET?**

HEAD asks for response headers only — the server must not include a body. This is all we need: the `Server:` header is in the response headers. GET would transmit the full response body for every probe, adding unnecessary bandwidth and latency.

**Why HTTP/1.0 and not HTTP/1.1?**

HTTP/1.1 keeps connections alive by default. After sending a response, the server waits for the next request. To know the response is complete under HTTP/1.1, the client must parse `Content-Length` or detect chunked encoding termination. HTTP/1.0 closes the connection after the response, so reading until EOF is sufficient. This simplifies the implementation significantly without affecting the information we need.

**Why `InsecureSkipVerify: true` for HTTPS?**

External scanning targets frequently present TLS certificates that are self-signed, expired, or issued to a different hostname. These are themselves security findings: a certificate error indicates misconfiguration that a real attacker would notice. If we refused to connect on certificate errors, we would hide the underlying service from scan results — the opposite of the goal. The `InsecureSkipVerify` flag is therefore not a security weakness in the scanner; it is a deliberate choice to maximise coverage.

### Banner parsing

Three parsers handle the most common cases.

**SSH** (`SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1`)

SSH sends its version string immediately on connection, before any client data. The format is defined in RFC 4253:

```
SSH-<protoversion>-<softwareversion>[ <comments>]\r\n
```

The software field uses an underscore to separate name from version (`OpenSSH_8.4p1`). A space followed by a comment is optional and is stripped. The result for the example above: `name="openssh"`, `version="8.4p1"`.

**HTTP** (`HTTP/1.x NNN ...\r\nServer: nginx/1.18.0\r\n...`)

The HTTP response headers are scanned line by line for a `Server:` header. The value format is `software/version [comment]`. The comment (e.g. `(Ubuntu)`) is stripped by taking only the first whitespace-delimited token after the version slash. If no `Server:` header is present, `name` is set to `"http"` — the port responded with HTTP but chose not to advertise the server software, which is itself useful to know.

**FTP / SMTP** (`220 ProFTPD 1.3.6 Server ready.`)

Both FTP and SMTP open connections with `220` greetings. The service is identified by keyword-matching against known software names in the banner text (`proftpd`, `vsftpd`, `pure-ftpd`, `postfix`, `sendmail`, `esmtp`). If none match, `name` is left empty rather than guessing — misclassification is worse than no classification.

### Read limit

All banner reads are capped at 4 096 bytes (4 KiB). This is enough to capture any HTTP response header block (which is the most data-rich banner type) while preventing memory exhaustion if a service streams data continuously. A partial read — receiving fewer than 4 096 bytes because the server closed the connection or the deadline fired — is not an error. Whatever bytes arrived are still processed.

---

## Pipeline integration (`cmd/asm/main.go`)

`main.go` is the only file that constructs concrete types. Every other file in the codebase works with interfaces. This means:

- Swapping `CTDiscoverer` for a different discovery source: change one line.
- Replacing `BannerFingerprinter` with one that uses nmap's service database: change one line.
- Adding PostgreSQL persistence via `Store`: add two lines (construct the store, call `store.Save(asset)`).

### New CLI flags (Phase 2)

```
--ports         Comma-separated TCP port list. Default: 21 common ports.
--workers       Goroutine pool size. Default: 100.
--scan-timeout  Per-connection deadline. Default: 2s.
```

The `--ports` flag accepts any comma-separated list of integers in the range 1–65535. Parsing is strict: non-integers and out-of-range values produce a descriptive error before any network activity begins.

The fingerprinter's timeout is set to `scan-timeout + 1 second`. The extra second accounts for the additional round-trip that fingerprinting requires (the scanner only needs to confirm a handshake; the fingerprinter must send a request and receive a response).

### Output structure

Phase 2 output groups results by asset, then by IP:

```
  api.example.com
    [1.2.3.4]
      22/tcp   openssh        8.4p1
      80/tcp   nginx          1.18.0
      443/tcp  nginx          1.18.0
    [5.6.7.8]
      22/tcp   openssh        8.4p1
      443/tcp  apache         2.4.41
```

Open ports are sorted by port number within each IP. Sorting is applied after all worker goroutines have finished, because goroutine scheduling order is non-deterministic — without sorting, the same scan of the same target could produce different output on each run.

When a port is open but fingerprinting fails or returns no service name, the port is still printed as `open` rather than being hidden. A known-open port with an unknown service is still a security finding.

---

## Testing strategy

The test suite uses only the Go standard library — no third-party testing frameworks.

### Table-driven tests

All unit tests use the table-driven pattern:

```go
tests := []struct {
    name   string
    input  string
    want   string
}{
    {"case A", "input-a", "expected-a"},
    {"case B", "input-b", "expected-b"},
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) { ... })
}
```

This separates the test logic from the test data, making it easy to add new cases without reading or modifying the assertion code.

### Real network listeners instead of mocks

The scanner and fingerprinter tests use `net.Listen("tcp", "127.0.0.1:0")` to bind a real local server on a random port:

```go
ln, _ := net.Listen("tcp", "127.0.0.1:0")
port := ln.Addr().(*net.TCPAddr).Port
```

The `:0` tells the OS to assign an unused port, avoiding conflicts between parallel test runs. This approach exercises the actual `net.DialTimeout` and `net.Conn` code paths through the OS network stack — not a mock that simulates those paths. It gives stronger confidence that the production code path works correctly.

### Error path coverage

Every test file contains at least one test for the error path — an invalid input, a closed port, or an unreachable address. Correct behaviour on the happy path does not guarantee correct behaviour when things go wrong; error paths are where most security tools fail in subtle ways.

### Package-internal test injection

The `BannerFingerprinter` tests are in `package fingerprint` (not `package fingerprint_test`), which gives them access to unexported fields. This allows a test to teach the fingerprinter that a specific local port speaks HTTP:

```go
f.httpPorts[port] = true
```

This avoids exporting the field (which would be a leaking internal detail) or adding a constructor overload only used in tests (which would pollute the API).

---

---

## Refactor & Bug-fix Pass (post Phase 2)

A full codebase review was conducted before moving to Phase 3. `go vet` and `-race` came back clean. Three issues were found and fixed.

### Bug fix — double deadline in `BannerFingerprinter`

**The bug:** `probeHTTP` called `conn.SetDeadline(now + timeout)` to bound the entire HTTP request-response cycle. It then called `readBanner`, which called `conn.SetReadDeadline(now + timeout)` *again* — resetting the read deadline to `timeout` measured from after the write finished, not from when the probe started. Result: an HTTP probe could silently take up to `2 × scan-timeout` instead of `scan-timeout`, hiding slow or misbehaving servers rather than timing them out correctly.

**The fix:** `readBanner` is now a pure reader — it does not touch the connection's deadline. Each caller owns its deadline:
- `grabRawBanner` calls `conn.SetReadDeadline(now + timeout)` after the dial (because `net.DialTimeout` only bounds the dial, not subsequent reads on the established connection).
- `probeHTTP` calls `conn.SetDeadline(now + timeout)` before writing (one deadline covers both the write and the read, as intended).

The principle: a helper function that reads from a connection should not have hidden side-effects on the connection's state. Deadline management is a caller responsibility.

### Bug fix — missing IP deduplication in `DNSResolver`

**The bug:** `net.LookupHost` can return duplicate addresses in some resolver configurations. Without deduplication, `asset.IPs` could contain the same IP address twice. In `main.go`, the output loop iterates `asset.IPs` once per entry — so a duplicate produces a duplicate output block for the same IP, and the scanner probes that IP twice and reports its ports twice.

**The fix:** `DNSResolver.Discover` now passes the raw IPs through `deduplicateIPs` before building the `Asset`. The helper uses a `map[string]struct{}` set to remove duplicates while preserving the original order returned by the resolver.

Deduplication lives in the resolver, not in the scanner or in `main.go`, because the resolver is where the invariant is established: "an `Asset.IPs` slice contains no duplicates." Enforcing it downstream would mean every consumer that receives an `Asset` has to remember to deduplicate — a leaking implementation detail.

### Missing test coverage — `parsePorts` and `filterByIP`

`parsePorts` is the user-input boundary in `main.go`. It does integer parsing, range validation (1–65535), and whitespace tolerance. All of these paths were untested. A new `cmd/asm/main_test.go` covers:
- Empty input returns the default port list.
- Valid comma-separated integers (including boundary values 1 and 65535).
- Invalid inputs: non-integers, zero, 65536, negative numbers, empty tokens from double-commas.
- `filterByIP` grouping logic: correct results for a matching IP, a non-matching IP, and an IP not in the list.

User-input handling is a system boundary. Per the project's testing convention, system boundaries must always be covered.

---

---

## Second Refactor Pass (pre Phase 3)

A second full codebase review before moving to Phase 3. `go vet` and `-race` again clean. Four issues found and fixed.

### Improvement — worker pool over-allocation in `TCPScanner`

With `--workers 100` and a small target (1 IP, 3 ports = 3 jobs total), 100 goroutines were started. 97 of them called `range jobs`, saw the already-closed channel, and exited immediately — goroutine initialisation cost with zero benefit. The pool is now capped to `min(s.workers, total)` using the Go builtin introduced in 1.21. For large scans (100 workers, 1 050 jobs) the behaviour is unchanged. For small scans the pool right-sizes itself.

### Refactor — flag variable naming in `main.go`

`portsFlag` had the `Flag` suffix but `workers` and `scanTimeout` did not. All three CLI flag pointer variables are now consistently named: `portsFlag`, `workersFlag`, `timeoutFlag`. Internal consistency in naming is important in code that will be read by academic reviewers.

### Documentation fix — misleading comment in `TestTCPScanner_Scan_MultipleIPs`

The comment said "simulate an asset that resolves to two IPs" but the asset's `IPs` slice contained `"127.0.0.1"` twice — the same address repeated. The test is actually verifying that the scanner does not deduplicate on its own (deduplication is the resolver's responsibility). The comment now accurately describes this: it confirms the scanner probes every `(IP, port)` pair it receives, even duplicates, producing 4 results for 2 ports × 2 IP entries.

### New test — HTTPS fingerprinting path (`grabHTTPSBanner`)

`grabHTTPSBanner` uses `tls.DialWithDialer` with `InsecureSkipVerify: true` — the only non-trivial code path with no test coverage. The test uses `net/http/httptest.NewTLSServer` (standard library), which creates a real TLS listener with a self-signed certificate. Because the fingerprinter intentionally skips certificate verification, the self-signed cert is not a problem — this is the exact same scenario as scanning an external host with a misconfigured or self-signed certificate. The test server responds with `Server: apache/2.4.41` and the fingerprinter correctly extracts name and version.

---

## Third Refactor Pass (pre Phase 3)

A third full codebase review before moving to Phase 3. `go vet`, `go build`, and `-race` all clean. Three issues found and fixed.

### Bug fix — `readBanner` single-read may miss multi-segment TCP responses

**The bug:** `readBanner` called `conn.Read(buf)` once and returned whatever bytes arrived. TCP is a stream protocol — a response can arrive in multiple segments (common with HTTP headers under load or across high-latency links). The first `Read` returns on the first segment, even if more bytes are already in the kernel buffer or arriving momentarily. This meant the `Server:` header in an HTTP response could be silently lost if it arrived in a second TCP segment, leaving the fingerprinter with no service name despite a successful probe.

**The fix:** `io.ReadAll(io.LimitReader(conn, int64(f.readLimit)))` loops internally until it receives EOF or an error. When the connection's deadline fires, `ReadAll` returns whatever was accumulated — so partial reads are still valid output. The `LimitReader` wrapper prevents memory exhaustion if a service streams data continuously. This is strictly more correct than a single `Read` with no additional complexity cost.

### Bug fix — `parseFTPSMTPBanner` wrong detection order causes misclassification

**The bug:** The FTP case was listed before the SMTP case and included the bare keyword `"ftp"`. A `220` greeting like `"220 smtp-ftp-relay.corp.com ESMTP Sendmail"` — where "ftp" appears only as a hostname component — would match FTP and never reach the SMTP case. A real-world SMTP server would be misclassified as FTP.

**The fix:** SMTP keywords (`postfix`, `sendmail`, `esmtp`, `smtp`) are now checked first. They are unambiguous identifiers that do not naturally appear in FTP banners. The bare `"ftp"` keyword stays in the FTP case but only fires after SMTP has been ruled out. A new test covers a Sendmail banner whose hostname contains "ftp" — confirming the ordering is now correct.

The principle: when multiple keyword sets have overlapping reach, check the most specific set first. "esmtp" in a banner unambiguously means SMTP; "ftp" in a banner is only reliable when no SMTP keyword is also present.

### Comment fix — misleading deadlock claim in `TCPScanner.Scan`

The closer goroutine comment claimed it "prevents a deadlock when the number of open ports exceeds the results channel buffer." The buffer is sized to `total` (every possible open port), so it can never be exceeded — the stated condition cannot occur. The comment now accurately describes the two real reasons the closer must run in a separate goroutine: the main goroutine is blocked draining results and cannot close the channel itself, and no individual worker finishing is sufficient to signal completion — only the WaitGroup knows when the last worker exits.

---

## Phase 3 — Cloud Bucket Hunting (`internal/cloudscan`)

### Why cloud bucket hunting belongs in an ASM engine

Cloud storage misconfigurations are among the most common and impactful findings in external attack surface assessments. An S3 bucket or Azure Blob container left publicly readable can expose customer data, credentials, source code, and internal documentation — all reachable without authentication by anyone who knows or guesses the URL. Organisations frequently forget these buckets exist: they were created for a one-off project, were never properly tagged, and have been sitting in the account for years.

Bucket hunting is an OSINT technique: it uses only public HTTP endpoints and known naming conventions. There is no contact with the target's own infrastructure. This makes it consistent with the engine's principle of passive, external-only reconnaissance.

### Interface design

```go
type HeadClient interface {
    Head(url string) (*http.Response, error)
}

type CloudScanner interface {
    Scan(domain string) ([]models.BucketResult, error)
}
```

**Why a new `HeadClient` interface rather than reusing `discovery.HTTPClient`?**

`discovery.HTTPClient` exposes only `Get`. Cloud bucket probing only ever needs `Head` — a `GET` would download the bucket's index page (potentially megabytes of XML) for every probe. Adding `Head` to `discovery.HTTPClient` would violate Interface Segregation: every struct in the `discovery` package would then depend on a method none of them call. The two interfaces stay narrow and independent. `*http.Client` satisfies `HeadClient` directly; no adapter is needed.

**Why `CloudScanner.Scan` accepts a domain string rather than a `[]models.Asset`?**

Cloud bucket names are derived from the target organisation's identity (its domain), not from specific live hosts. A bucket called `example-backup` has no relationship to any particular subdomain IP — it exists at the cloud provider's namespace. Accepting the raw domain string is the correct abstraction; passing a resolved asset would conflate two unrelated concepts.

### URL pattern generation

For a target domain like `example.com`, `candidatesFromDomain` derives:

- **Base label**: `example` (leftmost DNS label, which tends to be the organisation slug used in bucket naming)
- **Suffix variants**: `example-backup`, `example-dev`, `example-staging`, `example-prod`, `example-data`, `example-logs`, `example-assets`, `example-uploads`, `example-static`
- **Full domain slug**: `example-com` (dots replaced with hyphens — a common convention)

Each candidate is probed at three URL patterns:

| Provider    | URL pattern                                                   | Notes                                                   |
|-------------|---------------------------------------------------------------|---------------------------------------------------------|
| AWS S3      | `https://<name>.s3.amazonaws.com`                             | Virtual-hosted style — the primary pattern for modern S3 |
| AWS S3      | `https://s3.amazonaws.com/<name>`                             | Path style — legacy but still supported                 |
| Azure Blob  | `https://<name>.blob.core.windows.net/<name>?restype=container` | Container probe — returns 200/403 with clean semantics |

**Why the Azure container URL rather than the account root?**

The Azure Blob account root (`https://<name>.blob.core.windows.net`) returns `400 Bad Request` for existing accounts when no resource type is specified. This would require special-casing `400` alongside `200` and `403` in the status interpretation logic. The container URL (`?restype=container`) returns `200` for public containers and `403` for private ones — the same semantics as S3 — keeping the status interpretation uniform across both providers.

### Status code interpretation

| Status | Meaning         | Reported? | `Accessible` |
|--------|-----------------|-----------|--------------|
| 200    | Publicly readable — any unauthenticated request can list or read contents | Yes | `true` |
| 403    | Exists but private — confirms the storage asset is real even if not immediately exploitable | Yes | `false` |
| 404    | Not found — bucket name not registered at this provider | No (discarded) | — |
| Network error | DNS failure, timeout, connection refused | No (skipped) | — |

The 200/403 threshold is deliberately conservative. Treating only confirmed-present buckets as findings avoids false positives from servers that return unexpected status codes on their error pages. A network error skipping a candidate is not treated as "not found" — it means the probe could not reach the endpoint and the result is unknown.

### Sequential probing

Probes run sequentially. With 11 candidates × 3 URL patterns = 33 total HEAD requests, and cloud provider endpoints responding in under 100 ms on a typical connection, the total sweep completes in a few seconds. A concurrent pool would complicate the implementation — adding channel management, a WaitGroup, and a results collector — for a workload that is already fast. The Phase 2 port scanner demonstrated where concurrency delivers a 1 000× speedup; 33 sequential HTTP calls do not present that problem. The worker pool can be added later if profiling shows the candidate set has grown enough to warrant it.

### `BucketResult` in `pkg/models`

`BucketResult` is defined in `pkg/models` rather than `internal/cloudscan`:

```go
type BucketResult struct {
    URL        string
    Provider   string
    Status     int
    Accessible bool
}
```

The reason follows the same logic applied to `Asset` and `Service`: Phase 4 (PostgreSQL persistence) needs to store bucket findings in the database. If `BucketResult` lived inside `cloudscan`, the storage layer would have to import a business-logic package — violating Clean Architecture's dependency rule that inner layers must not know about outer ones. Placing it in the shared models package keeps both the scanner and the storage layer independent of each other.

---

---

## Fourth Refactor Pass (pre Phase 4)

A full codebase review before moving to Phase 4. `go vet`, `go build`, and `-race` all clean. Five issues found and fixed.

### Bug fix — Phase 3 bucket hunting silently skipped when no live assets found

**The bug:** `main.go` returned early when `len(liveAssets) == 0` — a guard placed before Phase 2 to avoid iterating over an empty slice. The return was positioned before the Phase 3 block too. Cloud bucket hunting (`BucketHunter.Scan`) takes a domain string, not a list of assets — it is completely independent of DNS resolution results. A target with no live subdomains can still have exposed S3 or Azure Blob storage. By returning early, an entire scan category was silently dropped.

**The fix:** Remove the early return. Wrap Phase 2 in `if len(liveAssets) > 0 { }` so the port scanner and fingerprinter are conditionally executed only when there are live assets to scan. Phase 3 sits outside the conditional and runs unconditionally for every target. A comment explains the asymmetry — the guard is not obvious to a reader who does not know that bucket hunting is domain-based.

The principle: an early return is correct when all remaining work is blocked. Here, only one of two remaining phases was blocked.

### Bug fix — `parseSubdomains` included SANs from unrelated domains

**The bug:** A TLS certificate can list many unrelated domains as Subject Alternative Names. A certificate issued for `example.com` might also cover `partner.org` or `vendor.io` in the same multi-domain cert. crt.sh returns all SANs for every certificate that matches `%.example.com`, so `parseSubdomains` could return hostnames like `other.org` that have no connection to the target. The DNS resolver would attempt to resolve them, they could appear in output as findings for the wrong target, and Phase 3 would generate bucket candidates based on them.

**The fix:** `parseSubdomains` now accepts a `targetDomain` parameter. After normalising each SAN to lowercase, it checks `name == target || strings.HasSuffix(name, "."+target)` and discards names that fail. The apex domain itself (`example.com`) and all of its subdomains (`api.example.com`, `*.example.com`) pass the filter; everything else is dropped. Two new test cases cover the filter: one for out-of-scope SANs in the same entry, one confirming the apex domain is kept.

### Improvement — `readBanner` misleading `(string, error)` return type

**The observation:** `readBanner` returned `(string, error)` but the body always returned `nil` for the error. The reason is correct design: `io.ReadAll` on a connection returns an error when the deadline fires (expected — the read window is over) or when the server closes the connection after sending its banner (benign — we already have the bytes). In both cases, the bytes already received are exactly what we want. Propagating those errors would cause callers to discard valid banner data, which is wrong. However, the `(string, error)` signature told callers "this can fail in a meaningful way", and their error checks were dead code.

**The fix:** Change `readBanner` to return just `string`. Each caller — `grabRawBanner` and `probeHTTP` — now returns `f.readBanner(conn), nil` explicitly, making it clear that the error path comes from the dial or write steps, not from banner reading. The doc comment explains the reasoning so a future reader understands why no error is returned.

### Improvement — `grabHTTPBanner` hardcoded `"tcp"` instead of `port.Proto`

**The observation:** `grabHTTPBanner` called `net.DialTimeout("tcp", addr, timeout)` with a hardcoded protocol, while `grabRawBanner` correctly used `port.Proto`. Although HTTP will always run over TCP in practice, the inconsistency could confuse a reader into thinking the two functions handle the `Proto` field differently for a principled reason. It also means that if `Port.Proto` ever carries a different value for protocol-level tunnelling, `grabHTTPBanner` would silently ignore it.

**The fix:** Replace `"tcp"` with `port.Proto` to match `grabRawBanner`'s approach and make the contract explicit: every fingerprinting method uses the transport protocol the scanner recorded.

### Improvement — `parsePorts` did not deduplicate repeated port numbers

**The observation:** `--ports 80,80,443` would scan port 80 twice per host, producing duplicate output lines for the same port. The scanner probes the same `(IP, port)` pair twice, the fingerprinter fingerprints it twice, and the output loop prints it twice — all redundant work.

**The fix:** Add a `map[int]struct{}` deduplication step inside the parsing loop. Ports that have already been added to the result slice are skipped with `continue`. Order is preserved (first occurrence wins). Two new test cases cover a simple duplicate and a case with multiple repeated ports interleaved.

---

---

## Fifth Refactor Pass (pre Phase 4)

A further full codebase review before moving to Phase 4. `go vet`, `go build`, and `-race` all clean. Two bugs and one improvement found and fixed.

### Bug fix — `parseHTTPBanner` panic on empty version after the slash

**The bug:** `parseHTTPBanner` parses a `Server:` header by splitting the value on `/` to separate the software name from its version: `"nginx/1.18.0"` → `["nginx", "1.18.0"]`. It then takes the first whitespace-delimited token from `parts[1]` using `strings.Fields(parts[1])[0]`. If a server emits `Server: nginx/` — a trailing slash with no version string — `parts[1]` is an empty string, `strings.Fields("")` returns an empty slice, and `[][0]` panics with an index-out-of-range error. Any server that sends this malformed-but-legal header would crash the fingerprinter mid-scan, halting Phase 2 entirely for the current asset.

**The fix:** Capture the result of `strings.Fields(parts[1])` in a variable and guard with `if len(fields) > 0` before indexing. When the version field is absent, `name` is still populated from `parts[0]` and `version` stays empty — the fingerprinter correctly reports the software name without a version, the same as for any other service that does not expose its version.

A new test case in `TestParseServiceBanner_HTTP` covers this: `"Server: nginx/"` must produce `name="nginx"`, `version=""` without panicking.

### Bug fix — trailing dot on `--target` silently filters out all discovered subdomains

**The bug:** `main.go` processed the `--target` flag with `strings.TrimSpace` only, leaving a trailing dot if the user supplied FQDN notation (e.g. `--target example.com.`). The domain string with the trailing dot was passed directly to `parseSubdomains` as `targetDomain`. Inside `parseSubdomains`, the scope filter computes `target = "example.com."` and then checks each lowercased SAN against `name != "example.com." && !HasSuffix(name, ".example.com.")`. Since crt.sh returns hostnames without trailing dots (e.g. `api.example.com`), every SAN fails both conditions and is discarded. The result: zero subdomains returned for any target written in FQDN form, with no error message — the pipeline runs but produces no findings.

**The fix:** Normalise the domain at the single entry point in `main()` before it is used anywhere:
```
strings.ToLower(strings.TrimRight(strings.TrimSpace(*target), "."))
```
`TrimRight` with `"."` strips all trailing dots. `ToLower` ensures the domain is in canonical lowercase before it reaches `parseSubdomains`, `BucketHunter`, and output formatting — eliminating the need for each internal function to independently handle mixed-case input. A comment in `main.go` explains all three operations and why each is necessary.

---

---

## Sixth Refactor Pass (pre Phase 4)

A full codebase review before moving to Phase 4. `go vet`, `go build`, and `-race` all clean. Three issues found and fixed.

### Fix — stale comment in `internal/discovery/http_client.go`

The `HTTPClient` comment said Phase 3 cloud scanning would reuse this interface. Phase 3 was implemented with its own `HeadClient` interface specifically to avoid reuse — adding `Head` to `HTTPClient` would have forced every discoverer to depend on a method it never calls. The comment was updated to explain the actual decision: two narrow interfaces are better than one wide one, even when the underlying type (`*http.Client`) satisfies both.

### Improvement — redundant `liveCount` variable in `main.go`

`liveCount` was incremented in exactly the same code path as `liveAssets = append(liveAssets, asset)`, making `liveCount == len(liveAssets)` an invariant that was never checked. Removing the variable and using `len(liveAssets)` directly eliminates one mental mapping — a reader no longer needs to verify that two things tracking the same quantity agree. A named `deadCount` variable was also introduced to make the summary line readable without mental arithmetic.

### Improvement — magic provider strings in `bucket_hunter.go`

`"aws_s3"` and `"azure_blob"` appeared as raw string literals in `buildURLs`. Adding a third AWS URL pattern in the future would require copy-pasting the string again. Named constants `providerAWSS3` and `providerAzureBlob` give the strings a single canonical location and make `buildURLs` self-documenting.

---

---

## Phase 4 — PostgreSQL Persistence (`internal/storage`)

### Why persistence transforms the engine

Without persistence, every scan run is independent. There is no answer to "when did this subdomain first appear?" or "was port 6379 open last week?" — the output is a point-in-time snapshot with no memory of previous states.

Persistence makes the engine a continuous monitoring tool. Running it daily against the same target and querying the database answers questions that matter to a security team:

- **New assets:** `first_seen` equals today's date → something appeared overnight.
- **Disappeared assets:** `last_seen` lags days behind today → a host went offline or changed DNS.
- **Service version changes:** the `version` column changed between runs → a service was upgraded or downgraded, which is both a change event and a potential CVE trigger.
- **Bucket accessibility changes:** a bucket that was `accessible = false` last week is now `accessible = true` → a misconfiguration was introduced.

### Interface design

```go
type Store interface {
    SaveAsset(asset models.Asset) error
    SavePort(domain string, port models.Port) error
    SaveService(domain string, svc models.Service) error
    SaveBucket(domain string, bucket models.BucketResult) error
    FindAssets() ([]models.AssetRecord, error)
    Close() error
}
```

**Why six methods rather than one `SaveAll`?** The pipeline saves findings as they are discovered, not in a batch at the end. An asset is saved immediately after DNS resolution, before port scanning begins. A port is saved before fingerprinting runs on it. Batching would require buffering the entire scan result in memory and writing it only on success — losing all findings if the process is interrupted mid-scan.

**Why is `Store` an interface rather than a concrete `*PostgresStore`?** The same reason every other dependency in the engine is an interface: `main.go` tests can inject an in-memory stub that verifies the correct methods are called without needing a live database. Phase 5 benchmarking can substitute a no-op store that discards everything to isolate scan performance from I/O performance.

**Why is the store optional (`--db` flag)?** The engine was useful before Phase 4 and must remain useful without a database. Making persistence opt-in means a quick one-off scan still works with a single flag, while production monitoring uses the full pipeline.

### `AssetRecord` in `pkg/models`

```go
type AssetRecord struct {
    Asset
    FirstSeen time.Time
    LastSeen  time.Time
}
```

`AssetRecord` embeds `Asset` rather than wrapping it in a named field. This means callers can write `record.Domain` and `record.IPs` directly without an extra dereference — the embedding makes it read as a natural extension of the asset rather than a database row.

Why does `AssetRecord` live in `pkg/models` and not in `internal/storage`? `FindAssets()` returns it, and `main.go` would need to import it to print the results. If it lived in `internal/storage`, `main.go` would import a package that also imports business-logic packages — the dependency would flow in the wrong direction. Placing it in the shared models package keeps both `storage` and `cmd` independent of each other.

Timestamps are not added to `Asset` itself for the same reason they were not added to `Port` or `Service`: those types are domain concepts (a hostname, a TCP port) with no inherent relationship to when they were observed. Timestamps are a persistence concern. Separating them keeps the domain model free of storage details.

### Database schema

```sql
CREATE TABLE assets (
    domain     TEXT        PRIMARY KEY,
    ips        TEXT[]      NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL
);

CREATE TABLE ports (
    asset_domain TEXT        NOT NULL REFERENCES assets(domain) ON DELETE CASCADE,
    ip           TEXT        NOT NULL,
    number       INTEGER     NOT NULL,
    proto        TEXT        NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (asset_domain, ip, number, proto)
);

CREATE TABLE services (
    asset_domain TEXT        NOT NULL,
    ip           TEXT        NOT NULL,
    port_number  INTEGER     NOT NULL,
    proto        TEXT        NOT NULL,
    name         TEXT        NOT NULL DEFAULT '',
    version      TEXT        NOT NULL DEFAULT '',
    banner       TEXT        NOT NULL DEFAULT '',
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (asset_domain, ip, port_number, proto),
    FOREIGN KEY (asset_domain, ip, port_number, proto)
        REFERENCES ports(asset_domain, ip, number, proto) ON DELETE CASCADE
);

CREATE TABLE bucket_results (
    url        TEXT        PRIMARY KEY,
    domain     TEXT        NOT NULL,
    provider   TEXT        NOT NULL,
    status     INTEGER     NOT NULL,
    accessible BOOLEAN     NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL
);
```

**Why natural keys rather than surrogate integer IDs?** A surrogate `id SERIAL` is convenient for joins but obscures the semantics of uniqueness. A domain is unique by definition — it cannot appear twice in the assets table. A `(asset_domain, ip, number, proto)` tuple uniquely identifies a port on an IP. Using natural keys makes the uniqueness constraint explicit in the schema and prevents the class of bugs where the same port is accidentally inserted twice with different surrogate IDs.

**Why `TIMESTAMPTZ` and not `TIMESTAMP`?** `TIMESTAMP WITHOUT TIME ZONE` stores values with no zone information. If the engine runs on a developer's laptop in Stockholm and the database server is in UTC, inserting `NOW()` in Go and reading it back would disagree by two hours — silently. `TIMESTAMPTZ` stores the UTC instant; the display timezone is a presentation detail. All writes go through `time.Now().UTC()` in Go regardless.

**Why `ON DELETE CASCADE` on ports and services?** If an asset is removed from the database (e.g. a cleanup script purging old records), its ports and services should be removed automatically. Requiring the caller to delete in three separate steps in the right order is an operational hazard. The cascade makes the database self-consistent by construction.

**Why `TEXT[]` for `ips` rather than a separate `asset_ips` table?** A normalised design would put each IP in its own row. That is the right design when IP records need to be queried individually, joined, or compared across assets. For this engine, IPs are always read and written as a unit alongside the domain — there is no use case for "give me all assets that share IP 1.2.3.4". The array column keeps the read and write paths simple without sacrificing any query that the current feature set requires.

### Upsert semantics

Every write uses `INSERT ... ON CONFLICT DO UPDATE`. This is PostgreSQL's atomic upsert: if the row does not exist, it is inserted; if it already exists, the specified columns are updated. The critical invariant is that `first_seen` is never included in the `DO UPDATE` clause — it is set only on the initial insert and never touched again. `last_seen` is always updated to `NOW()`.

```sql
INSERT INTO assets (domain, ips, first_seen, last_seen)
VALUES ($1, $2, $3, $3)
ON CONFLICT (domain) DO UPDATE
    SET ips       = EXCLUDED.ips,
        last_seen = EXCLUDED.last_seen
```

The `$3` appears twice in the VALUES clause — Go's `database/sql` resolves both positions to the same `now` variable. Using `EXCLUDED.last_seen` in the DO UPDATE clause picks up the value from the attempted insert row (which is `now`), rather than requiring a second `$4` parameter with the same value.

### Migration strategy

The schema DDL runs on every startup via `migrate()`, which executes the full `CREATE TABLE IF NOT EXISTS` block. This is idempotent — running it against an already-initialised database is a no-op. The engine does not need a separate migration tool or version table for a schema this size. If the schema needs to change in Phase 5, a new `ALTER TABLE` statement can be added to the migration function.

### Dependency: `github.com/lib/pq`

`lib/pq` is the only external dependency in the project. It is the standard PostgreSQL driver for Go's `database/sql` package — pure Go, no CGO, well-maintained, and the de-facto choice for production Go services that talk to PostgreSQL.

**Why not `pgx`?** `pgx` is a feature-rich PostgreSQL driver with native protocol support and a richer API. For this engine, `database/sql` + `lib/pq` is sufficient: we use standard SQL queries with positional parameters, and the only PostgreSQL-specific feature we rely on is `TEXT[]` arrays via `pq.Array`. Adding `pgx` would bring in a larger dependency for no material benefit at this scale.

### Integration tests

The `PostgresStore` tests are gated behind the `integration` build tag and require a `TEST_DB` environment variable pointing to a live PostgreSQL instance. This follows the same philosophy as the scanner tests — real infrastructure over mocks — but requires an opt-in to avoid failing in environments without PostgreSQL.

```
TEST_DB="postgres://user:pass@localhost/asmdb_test?sslmode=disable" \
go test -tags integration ./internal/storage/...
```

The tests verify:
- **New asset write:** `SaveAsset` creates a row; `FindAssets` returns it with non-zero timestamps.
- **Upsert preserves `first_seen`:** Calling `SaveAsset` twice with the same domain must advance `last_seen` while leaving `first_seen` unchanged.
- **Cascade correctness:** `SavePort` and `SaveService` succeed in order; subsequent upserts on the same keys do not error.
- **Bucket upsert:** Accessibility changes between calls are reflected in the stored row.

---

---

---

## Seventh Refactor Pass (post Phase 4)

A full codebase review after Phase 4 was shipped. `go vet`, `go build`, and `-race` all clean. One bug, two test gaps, and one stale documentation section found and fixed.

### Bug fix — banner data for unidentified services was silently discarded

**The bug:** In `main.go`, the guard before `store.SaveService` was `if err != nil || svc.Name == ""`. Both conditions triggered an immediate `continue`, so they were treated identically. This was wrong: when `err != nil`, fingerprinting failed at the network level (nothing to save), but when `err == nil && svc.Name == ""`, fingerprinting *succeeded* — it dialled, connected, and received a response — but could not classify the service from the banner. In the second case, `svc.Banner` may well be non-empty. That raw banner is exactly what the `Fingerprinter` interface contract promises to preserve:

> "It always returns a Service, even when identification is inconclusive. In that case, Name and Version will be empty strings and Banner will contain whatever raw bytes were received — preserving the evidence for manual analysis without treating ambiguity as a failure."

By collapsing both conditions into one `continue`, `SaveService` was never called for unidentified but banner-bearing services, silently discarding data that analysts would want to inspect.

**The fix:** Split the two conditions. `err != nil` still short-circuits immediately — a failed dial has nothing to save. `svc.Name == ""` no longer blocks persistence; instead, the save guard now checks `svc.Name != "" || svc.Banner != ""`. A service with an empty name but a non-empty banner is written to the database. Only when both are empty (the service accepted a connection but sent no data) is the write skipped — there is nothing useful to store in that case. The stdout output path is unchanged: a port with an unidentified service still prints as `open`.

The principle: the decision "should we persist this?" and the decision "should we print service details?" are independent. Collapsing them into one branch caused one to shadow the other.

### Test gap — `parseFTPSMTPBanner` default branch untested

**The gap:** `parseFTPSMTPBanner` handles three cases: SMTP keywords matched, FTP keywords matched, and a `default:` for any other "220" greeting. The existing tests covered only FTP and SMTP matches. No test verified that a "220" banner with no known keywords returns an empty name, leaving the `default:` branch permanently uncovered.

**The fix:** New test `TestParseServiceBanner_220Unknown` calls `parseServiceBanner("220 CUSTOM-SERVICE-GATEWAY READY")` and asserts both `name` and `version` are empty. The "220" prefix routes to `parseFTPSMTPBanner`, which finds no SMTP or FTP keyword and falls through to the default, confirming the function prefers no classification over a wrong one.

### Test gap — SMTP bare keyword coverage

**The gap:** The existing SMTP test cases both contained `"ESMTP"` in the banner. They verified `strings.Contains(lower, "esmtp")` but left the `"postfix"` and `"smtp"` branches of the switch untested. A regression that accidentally removed those keywords would go undetected.

**The fix:** Two new table-driven cases added to `TestParseServiceBanner_SMTP`:
- `"220 mail.example.com Postfix"` — exercises the bare `"postfix"` keyword without `"ESMTP"`.
- `"220 smtp.corp.com ready"` — exercises the bare `"smtp"` keyword.

---

---

---

## Eighth Refactor Pass (post Phase 4)

A second full codebase review after Phase 4 shipped, covering every file including `go.mod`, `Makefile`, `README.md`, and all test files. `go vet`, `go build`, and `-race` all clean. Seven issues found and fixed.

### Bug fix — `go.mod` marked `lib/pq` as an indirect dependency

**The bug:** `go.mod` contained `require github.com/lib/pq v1.12.3 // indirect`. The `// indirect` annotation means the package is not imported anywhere in the module itself — it is pulled in only because a direct dependency needs it. This was wrong: `internal/storage/postgres_store.go` imports `github.com/lib/pq` directly. A `// indirect` entry communicates a false contract to anyone reading the dependency tree and would cause `go mod tidy` to warn on future runs.

**The fix:** `go mod tidy` removed the annotation, leaving the entry as a plain direct dependency.

### Improvement — `TCPScanner.Scan` spawned a goroutine for zero work

**The observation:** When `total = len(asset.IPs) * len(s.ports) == 0` — which occurs if the asset has no IP addresses or the scanner is constructed with no ports — the code created two channels (capacity zero) and started a "closer" goroutine that called `wg.Wait()` (which returned immediately since no workers were spawned) and closed the results channel. The main goroutine's `for range results` then exited immediately. Correct result, but one goroutine allocation and channel creation for zero actual work.

**The fix:** An early return `if total == 0 { return nil, nil }` placed immediately after the `total` calculation. The zero-job path is now explicit and requires no channel machinery at all. The fix also documents the two reasons this case can arise: an asset with no IPs (rare but valid), and a scanner with no port list (a construction-time misconfiguration that parsePorts already prevents in practice).

### Test gaps — `Banner` field never asserted in HTTP and HTTPS fingerprint tests

**The gap:** `TestBannerFingerprinter_HTTPBanner` and `TestBannerFingerprinter_HTTPSBanner` verified `Name` and `Version` but never checked that `svc.Banner` was populated. The `main.go` banner-persistence fix introduced in the Seventh Refactor Pass relies on `svc.Banner != ""` to decide whether to write an unidentified service to the database. Without asserting the Banner, a regression that accidentally clears it would not be caught.

**The fix:** Both tests now assert `svc.Banner != ""` with a message that explains why the raw response must be preserved.

### New test — `TestBannerFingerprinter_SilentServer`

**The gap:** No test covered the case where a server accepts a TCP connection but sends nothing. This is the path where `io.ReadAll` returns empty bytes (either because the server closes immediately or because the read deadline fires). The expected outcome is: `err == nil`, `svc.Banner == ""`, `svc.Name == ""`. This is the "connected but unidentified" result that `main.go` uses to correctly skip persistence (both Name and Banner empty, nothing to store).

**The fix:** New test that starts a listener, accepts a connection, and immediately closes it without writing. The fingerprinter connects, reads until EOF, and returns a Service with both Banner and Name empty. The test asserts this and directly validates the contract that `main.go`'s persistence guard relies on.

### Documentation fixes

**README.md roadmap:** Only Phase 1a was checked as complete; Phases 1b through 4 are all shipped. Updated all four to `[x]`.

**`cmd/asm/main.go` pipeline doc comment:** The `SaveService` entry still said "persist identified service" after the previous fix changed the behavior to persist unidentified services with raw banners. Updated to "persist service when name or banner is present".

**`cmd/asm/main.go` Phase 2 block comment:** Said "Phase 4 tests can inject in-memory doubles" — an anachronism. Phase 4 is complete. Simplified to "tests can inject in-memory doubles".

**`Makefile` test target:** `go test -v ./...` did not include `-race`. The project's established convention is that `-race` is always required — the testing notes explicitly state: "`-race` is required — not optional." Updated to `go test -race -v ./...`.

---

## Phase 1 Extension — Multi-Source OSINT (Phases 1a–1d)

**Date:** 2026-05-03

The discovery stage was extended from a single CT log source to a four-step passive recon pipeline.

### Why extend Phase 1a to multiple sources?

A single source has inherent blind spots. Certificate Transparency logs only surface subdomains that have held a public TLS certificate. HackerTarget's passive DNS dataset captures plain-HTTP services and internal-only names that were never issued certificates. The Wayback Machine CDX API covers historical hostnames — subdomains that existed years ago, lost their certificate, but still have a live DNS record pointing at forgotten infrastructure. Using all three sources in parallel maximises coverage and makes the thesis argument for multi-source ASM measurably stronger.

### MultiSourceDiscoverer — the aggregation layer

Rather than adding sequential source calls to `main.go`, a `MultiSourceDiscoverer` encapsulates the fan-out and merge logic. `main.go` sees a single `SubdomainDiscoverer` interface — no knowledge of which concrete sources sit behind it. This follows the same dependency-inversion pattern used throughout the pipeline and keeps the wiring layer free of business logic.

Partial failure policy: if one source fails (e.g. HackerTarget returns 429 because the free-tier quota is exhausted), its results are silently skipped and the remaining sources still contribute. Only a total failure — every source erroring — is propagated to the caller. This mirrors a load balancer: one backend down must not abort the whole request.

The `Subdomain.Source` field records which source first found each hostname. Since deduplication preserves the first occurrence, a hostname found by both CT logs and HackerTarget is tagged `"ct_log"`. This gives Phase 5 clean per-source attribution data for coverage analysis.

### HackerTargetDiscoverer

API: `https://api.hackertarget.com/hostsearch/?q={domain}` — plain-text, one `hostname,ip` pair per line.

Key design decisions:
- A 429 response is treated as an empty result (not an error). The free-tier daily quota being exhausted is a transient infrastructure limit; aborting the pipeline over it would be wrong when two other sources can still run.
- Lines without a comma are silently skipped. HackerTarget embeds the error string "API count exceeded" directly in a 200 response body alongside normal data; this guards against that edge case.
- Source tag: `"hackertarget"`.

### WayBackDiscoverer

API: `https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=10000`

The CDX API returns a JSON array of string arrays. The first element is always a header row `["original"]`. Subsequent elements are archived URLs from which hostnames are extracted using `net/url.Parse` — this correctly strips ports, paths, and query strings that naive string splitting would mishandle. The `limit=10000` cap keeps response size predictable for popular domains with enormous archive histories.

Source tag: `"wayback"`.

### Phase 1c — PTR Reverse DNS Enrichment

After Phase 1b has resolved subdomains to IP addresses, a `PTREnricher` queries `net.LookupAddr` on every discovered IP. PTR records reveal sibling services on the same cloud infrastructure — services that never had public TLS certificates and were never indexed by any passive source.

A new `PTRResolver` interface (separate from the existing `Resolver`) follows Interface Segregation: `PTREnricher` only ever needs `LookupAddr`, and `DNSResolver` only ever needs `LookupHost`. Merging them would force every mock to stub a method it never uses.

Returned hostnames with a trailing FQDN dot (Go's `net.LookupAddr` convention) are trimmed before being passed to the DNS resolver. Each unique IP is queried at most once; the same hostname returned by multiple IPs is deduplicated. Source tag: `"ptr"`.

### Phase 1d — DNS Intelligence (TXT/MX service indicators)

The `DNSIntelligenceScanner` queries TXT and MX records for the target apex domain and extracts `ServiceIndicator` values for recognised third-party integrations.

**Why this matters for ASM:** SPF records expose every email and identity service the organisation has authorised (`include:mailgun.org`, `include:_spf.google.com`, etc.). These represent shadow IT — integrations added by individual teams that may not have undergone a security review. MX records identify the email provider, which is relevant for phishing risk assessment. Together they reveal an indirect attack surface that no amount of subdomain enumeration can surface.

Pattern matching uses substring containment against `spfIncludes` and `mxHosts` maps. A provider matched by multiple patterns in the same record (e.g. both `_spf.google.com` and `google.com` matching "Google Workspace") is reported once per record type. The same provider can appear as both a TXT indicator and an MX indicator — these are distinct findings with different evidence.

The `ServiceIndicator` type lives in `pkg/models` rather than `internal/discovery` because future persistence of these findings would require the storage layer to import the type. Placing it in `pkg/models` keeps all layers independent.

The `DNSIntelResolver` interface covers `LookupTXT` and `LookupMX` in a single interface because they are always queried together in a single scan and splitting them would provide no practical benefit.

### New files

| File | Purpose |
|------|---------|
| `internal/discovery/hackertarget_discoverer.go` | HackerTarget passive DNS API |
| `internal/discovery/wayback_discoverer.go` | Wayback Machine CDX API |
| `internal/discovery/multi_source_discoverer.go` | Fan-out aggregator |
| `internal/discovery/ptr_enricher.go` | Reverse DNS enrichment |
| `internal/discovery/dns_intel.go` | TXT/MX service indicator scanner |
| `pkg/models/asset.go` | Added `ServiceIndicator` type |

All new files follow the same interface-injection pattern as existing code. All new functionality is covered by table-driven unit tests using inline mocks; no external network calls are required by any test.

---

---

---

## Ninth Refactor Pass (pre Phase 5)

A full codebase review covering every file before Phase 5 benchmarking begins. `go vet`, `go build`, and `-race` all clean. No bugs found — eight previous refactor passes left the codebase sound. One UX improvement identified and applied.

### Improvement — Phase 1c and Phase 2 silently skipped when no live assets found

**The observation:** When Phase 1b discovers zero live hosts (all subdomains return NXDOMAIN, or the target has no discoverable subdomains), the pipeline skips Phase 1c (PTR enrichment) and Phase 2 (port scanning) without printing any message. The output jumps directly from the Phase 1b summary to Phase 1d (DNS intelligence), then to Phase 3 (cloud bucket scan). A user running the tool against a target with no live hosts sees no indication that two pipeline stages were intentionally omitted — it looks like those phases simply did not run, which is confusing when debugging a scan that returns fewer results than expected.

**The fix:** Both conditional blocks (`if len(liveAssets) > 0`) now have `else` branches that print a one-line skip message:
- `"Phase 1c: skipped — no live assets to enrich."`
- `"Phase 2: skipped — no live assets to scan."`

The messages match the tone and format of the other phase headers, keeping the output consistent across all execution paths.

The principle: every pipeline stage should be accounted for in the output, whether it ran, was skipped, or failed. Silent omissions make the tool harder to use and harder to debug.

---

## Tenth Refactor Pass (pre Phase 5)

Full codebase review before Phase 5 work begins. `go vet`, `go build`, and `-race` all clean after changes. Two correctness fixes and one fingerprinting gap closed.

### Fix 1 — `parseSPF` and `parseMX`: substring matching replaced with suffix/exact matching

**The bug:** Both functions used `strings.Contains(target, pattern)` to match SPF include targets and MX hostnames against known vendor patterns. This produces false positives: `strings.Contains("notmailgun.org", "mailgun.org")` is `true`, so any SPF include containing a vendor name as a substring of an unrelated domain would be misidentified.

**Why substring matching existed:** The intent was to catch legitimate subdomain variants — e.g. `include:eu.mailgun.org` should match the `"mailgun.org"` pattern. `strings.Contains` achieves this but overshoots.

**The fix:** Replace `strings.Contains` with `target == pattern || strings.HasSuffix(target, "."+pattern)`. This correctly handles:
- Exact match: `include:mailgun.org` → target `"mailgun.org"` == pattern `"mailgun.org"` ✓
- Subdomain variant: `include:eu.mailgun.org` → `HasSuffix("eu.mailgun.org", ".mailgun.org")` ✓
- False positive rejected: `include:notmailgun.org` → neither condition is true ✓

The same fix applies to `parseMX` — MX hosts like `aspmx.l.google.com` match `HasSuffix(host, ".google.com")` and are still correctly identified.

All existing tests pass unchanged; the fix is a strict improvement with no regressions.

### Fix 2 — POP3 and IMAP fingerprinting gap

**The gap:** Ports 110 (POP3) and 143 (IMAP) are in `defaultPorts`. The TCP scanner detects them as open, and `grabRawBanner` reads the greeting. However, `parseServiceBanner` had no branch for POP3's `+OK` greeting or IMAP's `* OK` greeting — they fell through to the empty-name default, leaving both services unidentified even though their banners were captured.

**The fix:** Added two cases to the `parseServiceBanner` switch and two parser functions — `parsePOP3Banner` and `parseIMAPBanner`. Both return a service name without a version, because neither protocol's greeting format has a reliable version field across implementations. Three new test cases each cover typical, alternative, and minimal greeting forms.

The change follows the existing SSH / HTTP / FTP-SMTP parser pattern exactly: one `case strings.HasPrefix(banner, ...)` in the switch, one dedicated parsing function, one test table in the test file.

---

## Eleventh Refactor Pass — Differential Analysis, Vulnerability Mapping, and Technology Stack Fingerprinting

One bug fix, one architectural comment, two storage methods, and three new packages. `go build`, `go vet`, and `go test -race ./...` all clean.

### Bug fix — false-positive SMTP classification in `parseFTPSMTPBanner`

`parseFTPSMTPBanner` matched the bare substring `"smtp"` in any 220 banner. A banner like `"220 ftp.smtp-gateway.example.com ProFTPD 1.3.6 Server ready."` contains `"smtp"` in the hostname and was misclassified as an SMTP server despite being FTP. The bare keyword was removed; the remaining identifiers — `"postfix"`, `"sendmail"`, `"esmtp"` — are unambiguous and sufficient for practical detection.

### Architectural comment — `probeHTTP` Host header limitation

`BannerFingerprinter.probeHTTP` sets `Host: ip:port`. On servers doing virtual hosting this produces a default-vhost response, not the intended site's response. Rather than change the `Fingerprinter` interface (a breaking change), a comment was added to `probeHTTP` documenting the limitation and pointing to `WebFingerprinter` as the architectural resolution.

### Storage layer — `FindPorts` and `FindServices`

Two read methods were added to the `Store` interface and implemented in `PostgresStore`:

- `FindPorts(domain string) ([]models.Port, error)` — queries the `ports` table ordered by `ip, number`.
- `FindServices(domain string) ([]models.Service, error)` — queries the `services` table ordered by `ip, port_number`.

Both are used by the differ to snapshot historical state before overwriting it with new scan results.

---

### Feature 1 — Differential Analysis (`internal/analysis`)

**Package:** `internal/analysis`
**New files:** `differ.go`, `differ_test.go`
**New model file:** `pkg/models/diff.go`

The differ computes what changed between the current scan and the previous scan stored in the database. It depends on a narrow `HistoryReader` interface (not `Store` directly — Interface Segregation), so it has no knowledge of PostgreSQL or any persistence mechanism.

**Types in `pkg/models/diff.go`:**

- `ChangeKind` — `"NEW ASSET"`, `"PORT OPENED"`, `"PORT CLOSED"`, `"VERSION CHANGE"`
- `AssetChange` — domain + kind
- `PortChange` — Port + kind
- `ServiceChange` — port, service name, old version, new version
- `ScanDiff` — all three change slices; `IsEmpty()` method

**`Differ` methods:**

- `DiffAssets(current []models.Asset)` — compares current domain list against historical `AssetRecord` set; emits `ChangeNewAsset` for domains not previously seen.
- `DiffAsset(domain string, currentPorts []models.Port, currentServices []models.Service)` — port diff is a symmetric set difference keyed on `ip:number/proto`; service version diff compares non-empty versions pairwise.

The differ is wired automatically in `main.go` whenever `--db` is supplied. The output block appears after Phase 2 completes:

```
--- Differential Analysis ---
[NEW ASSET]       dev-api.example.com (never seen before)
[PORT OPENED]     1.2.3.4:5432/tcp
[VERSION CHANGE]  nginx  1.18.0 → 1.24.0  (api.example.com)
(no changes)
```

---

### Feature 2 — Vulnerability Mapping (`internal/vulndb`)

**Package:** `internal/vulndb`
**New files:** `vulndb.go`, `vulndb_test.go`

`VulnDB` maps `(service name, version)` pairs to a hardcoded set of known CVEs. The matching logic handles two version formats:

- Dotted-decimal: `"1.18.0"`, `"2.4.49"` — standard `major.minor.patch` comparison.
- OpenSSH format: `"8.4p1"` — `p` is treated as an additional numeric component, so `"8.4p1"` becomes `[8, 4, 1]` for comparison.

`compareVersions(a, b string) int` returns −1/0/+1. Rules specify a `minVersion` and `maxVersion`; an empty bound means unbounded. An empty version passed to `Check()` returns no results (no guessing).

**Initial CVE dataset (15 rules):**

| Service | Rule | CVE | Severity |
|---------|------|-----|----------|
| openssh | < 9.8p1 (with min 8.5p1) | CVE-2024-6387 | CRITICAL |
| openssh | < 7.6 | CVE-2018-15473 | MEDIUM |
| apache  | 2.4.49–2.4.50 | CVE-2021-41773 | CRITICAL |
| apache  | < 2.4.52 | CVE-2021-44790 | HIGH |
| nginx   | < 1.20.1 | CVE-2021-23017 | HIGH |
| smtp    | unconditional | CVE-2023-51764 | HIGH |
| ftp     | unconditional | CVE-2023-48795 | HIGH |
| imap    | unconditional | CVE-2024-23184 | HIGH |
| pop3    | unconditional | CVE-2024-23184 | HIGH |
| http    | unconditional | — | LOW (informational) |

`VulnerabilityChecker` is an interface so `main.go` and tests can inject mocks or alternative implementations without coupling to `VulnDB` directly.

In `main.go`, after fingerprinting each service, matched CVEs are printed immediately below the service line:

```
      22/tcp   openssh   8.4p1
               [CRITICAL CVE-2024-6387: regreSSHion — unauthenticated RCE (pre-9.8p1)]
```

---

### Feature 3 — Technology Stack Fingerprinting (`internal/fingerprint`)

**New files:** `web_stack_fingerprinter.go`, `web_stack_fingerprinter_test.go`
**Modified:** `fingerprinter.go` (new `WebFingerprinter` interface)

`WebStackFingerprinter` issues a `GET / HTTP/1.1` with `Host: domain` (not `Host: ip:port`) and inspects both response headers and the first 8 KiB of the HTML body for technology signatures.

**Why GET instead of HEAD?** HEAD returns only headers. The highest-value technology signals — WordPress `wp-content/` paths, React `data-reactroot`, Next.js `__NEXT_DATA__` — live in the body. HEAD would miss all of them.

**Why a separate type from `BannerFingerprinter`?** Single Responsibility: `BannerFingerprinter` identifies the protocol and service software. `WebStackFingerprinter` identifies the application layer built on top. They operate at different abstraction levels (service vs. application) and different connection lifecycles (one-shot banner read vs. full HTTP/1.1 exchange).

**Detection coverage:**

- **Headers:** `X-Powered-By` (PHP, ASP.NET, Express, Next.js), `X-Aspnet-Version`, `X-Aspnetmvc-Version`, `X-Generator`, `X-Drupal-Cache`
- **Cookies:** `PHPSESSID`→PHP, `JSESSIONID`→Java/Tomcat, `ASP.NET_SessionId`→ASP.NET, `laravel_session`→Laravel, `_session_id`→Ruby on Rails
- **Body patterns:** `wp-content/`→WordPress, `sites/default/files`→Drupal, `__next_data__`→Next.js, `__vue_app__`→Vue.js, `ng-version=`→Angular, `data-reactroot`→React, `gatsby-announcer`→Gatsby, `__svelte`→Svelte

All body patterns are stored lowercase; matching is done against `strings.ToLower(body)` to ensure case-insensitive detection. Results are deduplicated by technology name.

In `main.go`, technology findings are printed below the service line on HTTP/HTTPS ports:

```
      443/tcp  nginx   1.18.0
               Tech: WordPress (CMS) — HTML: wp-content/ detected
               Tech: PHP (Language) — X-Powered-By: PHP/7.4.33
```

The `webServiceNames` map gates web fingerprinting to HTTP-speaking services (nginx, apache, iis, http, https) and the standard HTTP/HTTPS ports (80, 443, 8080, 8443, 8888), preventing wasted connections to SSH or database ports.

---

---

## Twelfth Refactor Pass

**Date:** 2026-05-04

Full code review after the Eleventh Refactor Pass. Two silent bugs discovered and fixed, one architectural constraint resolved, and one storage query added.

### Bug 1 — Service version diffs were always silent

**Root cause:** `Differ.DiffAsset` queried `FindServices` from the database internally. In `main.go`, `store.SaveService` was called for each port during the inner scan loop. By the time `DiffAsset` was invoked for services (after the inner loop), the database already held the *new* versions just written. `FindServices` returned the new version; comparing new vs new produced zero `ServiceChange` events. Every service upgrade between scan runs was silently swallowed — the differential output always showed "(no changes)" for service versions even when an upgrade had occurred.

The memory note said: *"Diff pre-snapshot must be taken BEFORE new scan results are saved to DB."* That rule was applied correctly for ports (the port diff call was before saves) but violated for services (the service diff call was after saves).

**The fix:** Separate DB-read from pure computation inside `Differ`.

`LoadAssetHistory(domain string) (*models.AssetHistory, error)` is a new method that fetches ports and services from the database in a single call. It is called in `main.go` once per asset, *before* any `SavePort` or `SaveService` call. The returned `*models.AssetHistory` is held in a local variable for the remainder of that asset's processing.

`DiffAsset` was refactored to accept a `*models.AssetHistory` parameter instead of reading from the database itself. It is now a pure function: no database access, no error return, deterministic output. Correctness proof: the snapshot was taken before any writes, so `history.Services` always contains the previous scan's versions, not the current one's.

### Bug 2 — PORT CLOSED events were never generated when all ports close

**Root cause:** When `tcpScanner.Scan` returned an empty port list, `main.go` printed "no open ports found" and immediately `continue`d to the next asset, skipping the diff block entirely. If an asset previously had open ports and now has none — a common scenario when a service is decommissioned or a firewall rule is tightened — zero PORT CLOSED events were emitted. The differential output for that asset was completely absent.

**The fix:** `LoadAssetHistory` is now called before the `len(openPorts) == 0` guard. When no ports are found, `DiffAsset` is still invoked with `nil` current ports and `nil` services. Because all history ports are absent from the (empty) current set, the pure comparison correctly emits a `ChangePortClosed` for every previously-open port. The asset continues to the next without further processing, but the diff is preserved for the summary block.

### Architectural issue — `Vulnerability` type location

**Problem:** `Vulnerability` and `Severity` were defined in `internal/vulndb`. The `pkg/models` package cannot import internal packages — that is a Go module rule, not a convention. This meant `models.Service` could not carry a `Vulnerabilities []Vulnerability` slice without creating an import cycle that the toolchain rejects.

**Why it matters:** Without this field, vulnerability results were only ever printed ad-hoc in `main.go`, not attached to the service struct. The service's full picture — identity, version, and known CVEs — was scattered across the pipeline rather than travelling together as one unit.

**The fix:** `Vulnerability` and `Severity` (type + four constants) were moved to `pkg/models/vulnerability.go`. `internal/vulndb` now imports from `pkg/models` — a legitimate dependency direction (internal packages are allowed to import pkg). The `VulnerabilityChecker` interface and `VulnDB` implementation stay in `internal/vulndb`; they are business logic, not data types.

`models.Service` gains a new field:

```go
Vulnerabilities []Vulnerability
```

In `main.go`, vulnerability annotation is now:

```go
svc.Vulnerabilities = vulnChecker.Check(svc.Name, svc.Version)
```

This happens before `SaveService` and before printing. The print loop iterates `svc.Vulnerabilities` directly — no second `Check` call needed. Vulnerabilities are not persisted (the `SaveService` SQL does not include the field) because CVE applicability must be recomputed fresh on every run; a stale snapshot from a past scan could report a CVE that was patched, or miss one that was added to the dataset since the last save.

### Storage enhancement — `FindAssetByDomain`

`FindAssets()` loads the entire assets table. For the differential analyser's new-asset detection, loading all records is correct and necessary. But for future point lookups — a query tool, a reporting layer, or Phase 5 analysis scripts that need one specific asset — reading the full table is wasteful.

`FindAssetByDomain(domain string) (*models.AssetRecord, error)` was added to both the `Store` interface and `PostgresStore`. It executes a single `WHERE domain = $1` lookup. The return convention is `(nil, nil)` when the domain is not found — not an error — so callers can distinguish "not in database" from a connection failure without error inspection.

### DiffAsset call count: 2 → 1 per asset

The previous code called `DiffAsset` twice per asset: once for ports (nil services), once for services (nil ports), then merged the results. Besides being the proximate cause of Bug 1, this pattern caused the database to be queried twice per asset and built port-change sets that were immediately discarded in the second call. After the refactor, `DiffAsset` is called once per asset with both `openPorts` and `scannedServices`. The snapshot is consistent, the computation is pure, and the result is complete in one pass.

### Test changes

- `differ_test.go` — `DiffAsset` tests no longer need a configured mock reader. The historical state is expressed directly as `&models.AssetHistory{Ports: ..., Services: ...}`, making the test setup more explicit and the intent immediately visible. A new case `"all ports closed — history had ports, current is empty"` was added to cover Bug 2's scenario.
- `differ_test.go` — `TestDiffer_LoadAssetHistory` added: three table-driven cases covering a domain with data, a reader error, and an unknown domain.
- `postgres_store_test.go` — `TestPostgresStore_FindAssetByDomain` added: integration test verifying `(nil, nil)` for missing domain, correct record retrieval after save.

---

## Thirteenth Refactor Pass (2026-05-04)

### DRY violation — portKey / svcKey

`DiffAsset` defined two local struct types with identical field layouts: `portKey` (`ip`, `number`, `proto`) and `svcKey` (same). A service is uniquely identified by its port coordinates, so `svcKey` was the same concept under a different name. The duplicate type was deleted; all service map lookups now use `portKey`. A single name for a single concept makes the relationship explicit and eliminates the risk of the two structs diverging in future edits.

### Decoupling — CanFingerprint removes port numbers from main.go

`main.go` previously contained five hardcoded port numbers (80, 443, 8080, 8443, 8888) to gate web technology fingerprinting. Those numbers duplicated the `httpPorts` / `httpsPorts` maps already inside `WebStackFingerprinter`. The wiring layer must not own knowledge about the fingerprinter's internal routing table — that violates the Dependency Inversion Principle.

`CanFingerprint(portNum int) bool` was added to the `WebFingerprinter` interface and implemented on `*WebStackFingerprinter` (returns true when portNum is in either internal map). `main.go` now calls `webFP.CanFingerprint(p.Number)` instead of spelling out the port list. Adding a new web port in the future requires changing one place — the `NewWebStackFingerprinter` constructor — not two.

### Named constants for HTTP client timeouts

Three HTTP client deadlines (30 s for crt.sh, 10 s for HackerTarget, 60 s for Wayback) were promoted from inline literals to named constants (`ctLogTimeout`, `hackerTargetTimeout`, `waybackTimeout`) with explanatory comments. The comments document *why* each timeout is the size it is, which would otherwise be opaque to a reader maintaining the pipeline.

### Silent error discard — documented intent

`doGET` in `WebStackFingerprinter` discards the error returned by `io.ReadAll`. This is intentional: a deadline firing or server-close after the response is the normal HTTP/1.1 termination path when `Connection: close` is set, and the bytes already accumulated are valid for fingerprinting. A comment was added to make the reasoning visible so future readers do not "fix" a deliberate choice.

The User-Agent string (`Mozilla/5.0`) was also extracted as a named constant (`userAgent`) with a comment explaining why a generic browser UA is preferred over a custom scanner string.

### Incorrect CVE comment

The inline comment for CVE-2021-44790 (Apache mod_lua) stated "NULL pointer dereference" but the CVE is a heap buffer overflow. The `Description` field below the comment already said "buffer overflow". The comment was corrected to match both the description and the actual vulnerability class.

### Performance — DB indexes for FindPorts and FindServices

`FindPorts(domain)` and `FindServices(domain)` both execute `WHERE asset_domain = $1`. The composite primary key `(asset_domain, ip, number, proto)` is not useful for a single-column equality predicate in PostgreSQL — the database cannot use the leading-column portion of the composite index to satisfy the WHERE clause without a partial index scan. PostgreSQL also does not automatically create indexes on foreign key columns (unlike primary keys).

Three `CREATE INDEX IF NOT EXISTS` statements were added to the schema:

```sql
CREATE INDEX IF NOT EXISTS idx_ports_asset_domain    ON ports(asset_domain);
CREATE INDEX IF NOT EXISTS idx_services_asset_domain ON services(asset_domain);
CREATE INDEX IF NOT EXISTS idx_buckets_domain        ON bucket_results(domain);
```

`IF NOT EXISTS` preserves idempotency consistent with the existing `CREATE TABLE IF NOT EXISTS` strategy. For the thesis scale (dozens of assets) the difference is negligible, but the indexes are correct regardless of scale and will matter for Phase 5 benchmarking on larger targets.

### Directory tree — updated to current state

The repository layout diagram was updated to reflect all packages added since the initial writing:
- `internal/discovery/` now lists all eight files (hackertarget_discoverer, wayback_discoverer, multi_source_discoverer, ptr_enricher, dns_intel added in Phases 1a–1d)
- `internal/fingerprint/` now lists `web_stack_fingerprinter.go`
- `internal/analysis/` and `internal/vulndb/` added (missing from earlier versions)
- `pkg/models/` now shows all three files: `asset.go`, `diff.go`, `vulnerability.go`

### Test additions

- `differ_test.go` — `TestDiffer_DiffAssets_Error`: exercises the `FindAssets()` error path; verifies a nil diff and non-nil error are returned when the reader fails.
- `differ_test.go` — `TestDiffer_DiffAsset_CombinedPortAndServiceChange`: a single `DiffAsset` call where a new port opens *and* a service version changes in the same scan. Verifies both appear in the result — the critical correctness invariant of the unified DiffAsset signature introduced in the Twelfth Pass.
- `web_stack_fingerprinter_test.go` — `TestWebStackFingerprinter_CanFingerprint`: table-driven test covering all five HTTP/HTTPS ports (expect true) and three non-web ports (expect false).

---

## What comes next

### Phase 5 — Go vs Python benchmarking

This is the core academic deliverable. The same pipeline will be implemented in Python using `asyncio` for I/O concurrency. Go's results will be compared against Python's on:

- Total scan time for the same target
- Peak memory usage
- Lines of code required to implement equivalent functionality
- Behavioural correctness under load (correct handling of timeouts, partial reads, concurrent resource limits)

The worker pool in Phase 2a is the primary subject of this comparison. Go's goroutines are lightweight (2–8 KB initial stack vs. a Python thread's 1–8 MB), which means a Go pool of 100 workers uses roughly 1–2 MB of stack memory. A Python equivalent using threads would use significantly more. The benchmark will quantify this difference under controlled conditions.

---

## Fourteenth Refactor Pass (2026-05-04)

A second full-codebase audit after the Thirteenth Pass. Seven confirmed issues addressed. All changes pass `go test -race ./...`, `go vet ./...`, and `go build ./...`.

### 1. Port constants DRY — new `internal/fingerprint/ports.go`

`NewBannerFingerprinter` and `NewWebStackFingerprinter` each hardcoded identical maps (`{80, 8080, 8888}` for HTTP and `{443, 8443}` for HTTPS). Adding a non-standard port required editing two constructors in two structs. Fix: new file `internal/fingerprint/ports.go` with package-level `defaultHTTPPorts []int`, `defaultHTTPSPorts []int`, and a `buildPortMap([]int) map[int]bool` helper. Both constructors now call `buildPortMap(defaultHTTPPorts)` and `buildPortMap(defaultHTTPSPorts)` — one file to update, one concept per name.

### 2. Performance — `MultiSourceDiscoverer` concurrent fan-out

Sources were queried sequentially. With three sources at 30 s / 10 s / 60 s timeouts, worst-case Phase 1a latency was their sum (~100 s). Each source now runs in its own goroutine; results are written to pre-indexed slots (`results[i]`) so no mutex is required during collection. A `sync.WaitGroup` signals completion; the merge happens sequentially in original source order, which preserves the first-source-wins deduplication guarantee. Worst-case latency is now the maximum single-source timeout (~60 s). This is also a Phase 5 thesis argument: Go makes goroutine-based fan-out concise and safe.

### 3. Memory efficiency — HackerTarget streaming

`HackerTargetDiscoverer.Discover` used `io.ReadAll(resp.Body)` to buffer the entire response before parsing, while CT and WayBack both stream-decode their responses. Fix: replaced `io.ReadAll + parseHackerTargetLines` with an inline `bufio.NewScanner(resp.Body)` loop. Peak memory is now proportional to the longest single line rather than the full response. The now-unused `parseHackerTargetLines` function was deleted; all existing tests exercised `Discover` via a mock HTTP client and pass unchanged.

### 4. Bug — empty domain silently probed malformed URLs

`BucketHunter.Scan("")` called `candidatesFromDomain("")`, which produced candidates like `""` and `"-backup"`. These generated probe URLs such as `"https://.s3.amazonaws.com"` — structurally malformed but silently skipped at the DNS/HTTP layer with no error. Fix: early-return guard at the top of `Scan`: if `domain == ""` return `nil, nil` immediately. A test case was added to `bucket_hunter_test.go` verifying that an empty domain produces zero results.

### 5. Output label inconsistency — `[public]`

Every output label in the CLI was lowercase (`[live]`, `[dead]`, `[ptr-live]`, `[private]`) except the accessible-bucket label, which was `[PUBLIC]`. Changed to `[public]` to match the rest of the output format.

### 6. Misleading test comment — `vulndb_test.go`

The test case for `"apache version predating traversal range"` (version 2.4.41) had a comment saying "traversal rule should NOT fire" with `wantNone: false`. The comment explained only the rule that *doesn't* fire, not why the test expects a result. Rewritten: the comment now explains that the path-traversal CVE (min 2.4.49) does not fire, but the mod_lua buffer-overflow CVE (max 2.4.51, no minVersion) does fire because 2.4.41 ≤ 2.4.51.

### 7. Undocumented behaviour — `splitVersion` distro suffixes

`splitVersion("1.18.0-ubuntu1")` silently produces `[1, 18, 0]` because `strconv.Atoi("0-ubuntu1")` fails and is treated as zero. This is correct for the CVE dataset (all bounds are clean dotted-decimal or OpenSSH p-notation), but was invisible to future maintainers. A comment was added in `splitVersion` explaining the approximation. A test case was added to `TestCompareVersions`: `{"distro suffix treated as zero component", "1.18.0-ubuntu1", "1.18.0", 0}`.

### Files modified

| File | Change |
|------|--------|
| `internal/fingerprint/ports.go` | **New** — shared port slices + `buildPortMap` helper |
| `internal/fingerprint/banner_fingerprinter.go` | Constructor uses `buildPortMap(defaultHTTPPorts/HTTPSPorts)` |
| `internal/fingerprint/web_stack_fingerprinter.go` | Constructor uses `buildPortMap(defaultHTTPPorts/HTTPSPorts)` |
| `internal/discovery/multi_source_discoverer.go` | Concurrent fan-out with `sync.WaitGroup`; merge in source order |
| `internal/discovery/hackertarget_discoverer.go` | `bufio.Scanner` streaming; `parseHackerTargetLines` deleted |
| `internal/cloudscan/bucket_hunter.go` | Empty domain guard at top of `Scan` |
| `internal/cloudscan/bucket_hunter_test.go` | Empty domain test case |
| `cmd/asm/main.go` | `[PUBLIC]` → `[public]` |
| `internal/vulndb/vulndb_test.go` | Misleading comment rewritten; distro-suffix test case added |
| `internal/vulndb/vulndb.go` | `splitVersion` comment explaining distro-suffix approximation |

---

## Fifteenth Improvement Pass (2026-05-04)

Four pre-Phase-5 improvements. All changes pass `go test -race ./...`, `go vet ./...`, and `go build ./...`.

### 1. README — stale roadmap and missing flags

The roadmap showed only Phases 1a, 1b, 2, 3, 4. Phase 1c (PTR enrichment), Phase 1d (DNS intelligence), and the three advanced features (Differential Analysis, Vulnerability Mapping, Technology Stack Fingerprinting) were absent. A Chalmers evaluator or open-source contributor reading the README would have no idea these existed. The roadmap now lists all ten completed items. The Quick Start block now shows all CLI flags with annotated examples including `--rate-limit`.

### 2. GCP Cloud Storage — `internal/cloudscan/bucket_hunter.go`

`BucketHunter` previously covered AWS S3 and Azure Blob but not Google Cloud Storage — the third major cloud provider. Its absence was a gap in the attack surface coverage argument.

Added `providerGCPStorage = "gcp_storage"` constant. `buildURLs` now generates two GCP patterns per candidate name:

- **Path-style**: `https://storage.googleapis.com/<name>` — the standard XML API pattern. Public buckets return 200, private return 403, absent return 404 — same semantics as S3.
- **Virtual-hosted**: `https://<name>.storage.googleapis.com` — used by some CDN and SDK configurations.

Each candidate now produces 5 probe URLs total (2 AWS + 1 Azure + 2 GCP). Four new test cases were added: GCP path-style public, GCP virtual-hosted private, three-provider combined, and the existing tests pass unchanged (mock defaults to 404 for unregistered URLs).

### 3. Rate limiter — `internal/scanner/tcp_scanner.go`

The project constraints state "network rate-limiting to avoid DoS classification" but there was no explicit rate limiter — only implicit limiting via `--workers` count and `--scan-timeout`. This made the DoS-avoidance claim indefensible in the thesis and gave Phase 5 benchmarking no controlled variable for connection rate.

`TCPScanner` gains a `rateLimit int` field (max dial attempts per second; 0 = unlimited). When `rateLimit > 0`, a `time.NewTicker(time.Second / rateLimit)` feeds a `tokens <-chan time.Time` channel. Each worker reads one token before each dial attempt. Because the channel is shared across all goroutines, exactly `rateLimit` tokens are consumed per second globally — regardless of pool size.

**Critical invariant**: `time.NewTicker` creates an empty channel. The first tick arrives after the first full interval (`1/rateLimit` seconds). The throttle applies from the very first dial — there is no "free first connection." `defer ticker.Stop()` is safe: it runs only after `Scan` returns, which only happens after all workers finish draining the jobs channel (via `wg.Wait()` → `close(results)` → `for range results` completes).

The `--rate-limit` flag wires this into the CLI. The Phase 2 header line prints the active rate when non-zero: `"... 10 conn/s rate limit..."`.

`NewTCPScanner` gains a fourth parameter `rateLimit int`; negative values are clamped to 0. New tests: `TestTCPScanner_Scan_WithRateLimit` (correctness at rateLimit=1000) and `TestNewTCPScanner_NegativeRateLimitClampedToZero`.

### 4. `run()` extraction — `cmd/asm/main.go`

`main.go` had ~200 `fmt.Printf` calls inline in the pipeline. `main_test.go` could only test `parsePorts` and `filterByIP` — the entire pipeline orchestration was untestable without capturing `os.Stdout` globally.

`main()` is now 4 lines. All pipeline logic lives in `run(w io.Writer, args []string) error`. This pattern follows the standard Go CLI idiom and satisfies SOLID:

- **D (Dependency Inversion)**: `run` depends on `io.Writer` (stdlib interface), never on `os.Stdout` (concrete type).
- **I (Interface Segregation)**: `io.Writer` is a single-method interface — the narrowest possible output contract. A custom `Reporter` with named methods would have been over-abstracted for this use case.
- **O (Open/Closed)**: New output targets (JSON, structured logs, `io.Discard` for benchmarks) require zero changes to `run`.

`flag.NewFlagSet` replaces the global `flag.CommandLine` — no state leaks between test calls. All `fmt.Printf` → `fmt.Fprintf(w, ...)`. Fatal config errors returned as `error`; non-fatal store/scan errors kept as `log.Printf` to stderr (correct separation: scan output on stdout, error noise on stderr). `flag.ErrHelp` handled explicitly — `--help` returns nil.

Three new tests exercise `run()` directly via `bytes.Buffer`: `TestRun_MissingTarget`, `TestRun_InvalidPorts`, `TestRun_HelpFlag`.

### Bug fixed

`internal/scanner/tcp_scanner.go` comment incorrectly stated "ticker.C has a buffer of 1, so the very first dial starts immediately." `time.NewTicker` creates an empty channel; the first value arrives after one full interval. The comment was corrected to accurately describe the behaviour.

### Files modified

| File | Change |
|------|--------|
| `README.md` | Roadmap + Quick Start fully updated |
| `internal/cloudscan/bucket_hunter.go` | `providerGCPStorage` constant; two GCP URL patterns in `buildURLs` |
| `internal/cloudscan/bucket_hunter_test.go` | Four new GCP and multi-provider test cases |
| `internal/scanner/tcp_scanner.go` | `rateLimit` field; ticker token channel in `Scan`; comment bug fixed |
| `internal/scanner/tcp_scanner_test.go` | Fourth arg on all `NewTCPScanner` calls; two new rate-limit tests |
| `cmd/asm/main.go` | `run(w io.Writer, args []string) error` extraction; `--rate-limit` flag; `flag.NewFlagSet` |

---

## Final Phase — Localhost Web UI Dashboard + Sandboxed Docker Environment (2026-05-05)

### What was built

The engine now ships with an embedded, zero-dependency web UI accessible via `--ui`. A sandboxed Docker environment enables safe local evaluation against a deliberately vulnerable target.

### Architecture: typed event channel

The core design challenge was that `cmd/asm/main.go:run()` wrote formatted strings to an `io.Writer`. A web UI requires structured, typed data. The solution avoids duplicating the 500-line pipeline: a new `internal/pipeline` package introduces a typed event channel between the engine and its consumers.

```
PipelineRunner.Run(ctx, cfg) → <-chan ScanEvent
          │
    ┌─────┴──────────────────────────────────┐
    │                                        │
CLI consumer                        SSE handler
(cmd/asm/main.go)               (internal/web/server.go)
reads events, formats text      encodes events as JSON,
to io.Writer (unchanged output) flushes per event via http.Flusher
```

**Why this design, not wrapping io.Writer?** Wrapping io.Writer would deliver text blobs to the frontend — unparseable for the four visual cards. Typed events let the JavaScript `EventSource` client route each event to the correct card via named `addEventListener` listeners, with no secondary parsing.

### `internal/pipeline/events.go`

Defines `ScanEvent{Type EventType, Payload json.RawMessage}` and all payload structs. `json.RawMessage` as the payload field means each phase marshals once; both consumers unmarshal only what they need. A `newEvent` helper panics at development time if a payload is not JSON-serialisable — it is never reachable in production.

### `internal/pipeline/runner.go`

`Runner` holds every concrete implementation (subdiscoverer, scanner, fingerprinters, vulnchecker, cloud scanner, store, differ). `NewRunner(cfg)` is the single instantiation point — both the CLI and the SSE handler call it. `Run(ctx, cfg)` spawns exactly one goroutine; the goroutine exits when the pipeline finishes or `ctx` is cancelled (browser tab closed). This is the only new goroutine introduced — warranted because the HTTP handler must not block.

`IsLocalTarget(target)` returns true for IP addresses (`net.ParseIP`) or bare hostnames without dots (Docker service names). Local targets bypass Phases 1a–1d and build a synthetic `models.Asset` via `buildSyntheticAsset`, which tries OS DNS resolution and falls back to using the name itself so Docker bridge names resolve at scan time.

### `cmd/asm/main.go` refactor

`run(io.Writer, []string) error` keeps its exact signature — `main_test.go` calls it unchanged. The 500-line pipeline body is replaced by flag parsing → `pipeline.NewRunner(cfg)` → `consumeForCLI(w, events)`. `consumeForCLI` reproduces every `fmt.Fprintf` line from the original implementation by formatting events back to text; the CLI output is byte-for-byte identical to before.

`main()` pre-scans `os.Args` for `--ui` before delegating to `run()`. This avoids adding `--ui` to `run()`'s `flag.FlagSet` (which would require making `--target` optional for UI mode, breaking `TestRun_MissingTarget`).

### `internal/web/server.go` — SSE streaming

SSE was chosen over WebSockets because it is one-directional (scan results only flow server→client), natively supported by browsers via `EventSource`, and requires no library. The `event:` field in each SSE message is set to the `EventType` string so the frontend uses `addEventListener('port', handler)` — no secondary type-switch in JavaScript.

`http.Flusher.Flush()` is called after every event write. `r.Context()` is passed to `runner.Run()` — Go's HTTP server cancels it automatically when the client disconnects, propagating cancellation into the pipeline goroutine.

### `internal/web/static/index.html`

Single self-contained file — no build step, no node_modules, no CDN dependencies. Embedded via `//go:embed static/index.html` so the binary is fully self-contained. Four live cards:
- **Subdomains & Assets** — `[NEW]` badge (blue) when diff detects a new domain
- **Ports & Infrastructure** — inline CVEs, tech stack, `[OPENED]` badge (amber) for new ports
- **Cloud Buckets** — `[PUBLIC]` (red) / `[PRIVATE]` (green) per `BucketPayload.Accessible`
- **DNS Intelligence & Progress** — third-party service indicators + real-time phase progress

All user-facing strings inserted via `innerHTML` pass through `esc()` to prevent XSS from scan results containing HTML characters.

### Docker environment

- `deploy/Dockerfile` — multi-stage build (`golang:1.25-alpine` → `alpine:3.20`). `CGO_ENABLED=0` produces a fully static binary; `ca-certificates` is added for HTTPS to OSINT sources. Default `CMD ["--ui"]`.
- `deploy/docker-compose.yaml` — three services on `asm-net` bridge:
  - `db` — PostgreSQL 16-alpine, healthcheck-gated, schema loaded from `deploy/db/init.sql`
  - `victim-service` — nginx 1.14.0-alpine (deliberately old; exposes CVE-2019-9511/9513 for Phase 2 demo)
  - `asm-engine` — our binary, UI on host port 8080, `depends_on: db: condition: service_healthy`
- `deploy/db/init.sql` — schema DDL kept in sync with `internal/storage/postgres_store.go`

### Test compatibility

All pre-existing tests pass without modification (`go test -race ./...` green). The refactor preserved every public function signature. `parsePorts()` and `filterByIP()` remain in `cmd/asm/main.go` (package `main`) because `main_test.go` references them directly.

### Files added

| File | Purpose |
|------|---------|
| `internal/pipeline/events.go` | `ScanEvent` envelope + all payload types + `newEvent` + `emit` |
| `internal/pipeline/runner.go` | `Config`, `Runner`, `NewRunner`, `Run`, `IsLocalTarget`, `buildSyntheticAsset` |
| `internal/web/server.go` | `Serve`, SSE handler `handleScan`, query-param config parsing |
| `internal/web/static/index.html` | Dark-mode SPA — four live cards, EventSource client, XSS-safe rendering |
| `deploy/Dockerfile` | Multi-stage Go build → alpine runtime |
| `deploy/docker-compose.yaml` | Three-service sandbox: db + victim + engine |
| `deploy/db/init.sql` | Schema DDL for Postgres container initialisation |

### Files modified

| File | Change |
|------|--------|
| `cmd/asm/main.go` | `run()` slimmed to flag parsing + `consumeForCLI`; `main()` gains `--ui` routing; `internal/pipeline` and `internal/web` imports added |
| `cmd/asm/main_test.go` | Three new `run()` tests |
