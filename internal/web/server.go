// Package web implements the HTTP server that exposes the DASM web UI.
//
// It serves a single embedded HTML+CSS+JS file at GET / and streams scan
// results as Server-Sent Events at GET /scan?target=<domain>. The HTML and
// the SSE protocol are the only external interfaces — no JSON REST API is
// needed because the frontend is a purpose-built consumer of the event stream.
//
// The embedded static asset is compiled into the binary via //go:embed so the
// final binary is self-contained: no separate web server, no static file
// directory, no runtime file system dependencies.
//
// The /scan endpoint is unauthenticated by design — it is intended for
// single-operator, local-network use. For multi-user or cloud deployments,
// place a reverse proxy with authentication in front of this server.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/arvin-sudo/asm-engine/internal/pipeline"

	_ "embed"
)

//go:embed static/index.html
var indexHTML []byte

// Serve starts the HTTP server on addr (e.g. ":8080") and blocks until ctx is
// cancelled or an unrecoverable error occurs. It registers two routes:
//
//	GET /       — the embedded single-page UI
//	GET /scan   — SSE event stream; requires ?target=<domain>
//
// When ctx is cancelled (e.g. SIGINT) the server shuts down gracefully,
// waiting up to 5 seconds for in-flight requests to complete.
func Serve(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/scan", handleScan)

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		// Conservative timeouts: SSE connections are long-lived, so only the
		// header phase needs a deadline. WriteTimeout is omitted intentionally —
		// setting it would cut off streaming responses mid-scan.
		ReadHeaderTimeout: 10 * time.Second,
		// Explicit cap on request header size; the default is also 1 MiB but
		// naming it here makes the constraint visible and prevents silent
		// dependency on an undocumented default.
		MaxHeaderBytes: 1 << 20,
	}

	// Shut down gracefully when the parent context is cancelled.
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	return srv.ListenAndServe()
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	// Only serve the root path; 404 everything else that isn't /scan.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Defence-in-depth headers: prevent MIME-sniffing, deny framing, and
	// restrict resource loading to same-origin. The embedded HTML has no
	// external dependencies so 'self' is the correct CSP scope.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	if _, err := w.Write(indexHTML); err != nil {
		// The client disconnected before the full page was delivered.
		// Nothing meaningful can be sent in response — log and return.
		log.Printf("web: serveIndex: write: %v", err)
	}
}

// handleScan is the SSE endpoint. It reads ?target=<domain> from the query
// string, constructs a pipeline.Runner, and streams every ScanEvent as an SSE
// message until the scan completes or the client disconnects.
//
// Each SSE message uses the event: field set to the EventType string so the
// JavaScript client can use named addEventListener listeners instead of the
// generic onmessage handler — this routes events to the correct card without
// a secondary JSON parse.
func handleScan(w http.ResponseWriter, r *http.Request) {
	// SSE requires these headers to be sent before the first byte of body.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Allow the browser to open an EventSource from any page origin.
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// http.Flusher is implemented by Go's standard ResponseWriter when the
	// connection supports streaming. If it is missing, SSE cannot work.
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported by this server", http.StatusInternalServerError)
		return
	}

	// Acquire a scan slot before doing any further work. The non-blocking select
	// means callers are rejected immediately rather than queued — under load the
	// server stays responsive for new connections even while at capacity.
	select {
	case scanSemaphore <- struct{}{}:
		defer func() { <-scanSemaphore }()
	default:
		writeSSEError(w, flusher, "server at capacity, try again shortly")
		return
	}

	target := strings.TrimSpace(r.URL.Query().Get(queryParamTarget))
	if target == "" {
		writeSSEError(w, flusher, "target query parameter is required")
		return
	}

	// Block direct scans of loopback, RFC 1918, and link-local addresses. These
	// ranges should never be reachable from an external attack surface scanner;
	// allowing them from the web UI would let any browser tab probe internal
	// infrastructure (SSRF). Hostname targets pass through — the discovery layer
	// scopes results to the declared target domain.
	if isPrivateTarget(target) {
		writeSSEError(w, flusher, "scanning private or reserved IP ranges is not permitted")
		return
	}

	cfg := buildConfig(r, target)
	runner, err := pipeline.NewRunner(cfg)
	if err != nil {
		// Redact the DSN before logging — a postgres connection error includes the
		// full DSN (with credentials) in its message. The client receives only a
		// generic message to avoid leaking internal configuration.
		logMsg := err.Error()
		if cfg.DSN != "" {
			logMsg = strings.ReplaceAll(logMsg, cfg.DSN, "[DSN redacted]")
		}
		log.Printf("web: handleScan: runner init: %v", logMsg)
		writeSSEError(w, flusher, "Failed to initialise scanner. Check server logs.")
		return
	}
	defer runner.Close()

	// r.Context() is cancelled automatically by Go's HTTP server when the
	// client closes the tab or connection. Passing it to Run propagates the
	// cancellation into the pipeline goroutine so it exits cleanly.
	for e := range runner.Run(r.Context(), cfg) {
		b, err := json.Marshal(e)
		if err != nil {
			// ScanEvent and all payload types are controlled structs with no
			// un-marshalable fields — this branch is unreachable in practice, but
			// logging it ensures we notice if a future payload type breaks the invariant.
			log.Printf("web: handleScan: marshal event %s: %v", e.Type, err)
			continue
		}
		// SSE wire format:
		//   event: <type>\n
		//   data: <json>\n
		//   \n
		// The blank line terminates the event and triggers dispatch in the browser.
		// A write error means the client disconnected — stop streaming immediately
		// rather than burning CPU finishing a scan nobody receives.
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, b); err != nil {
			return
		}
		flusher.Flush()

		// Check for client disconnect between events to avoid writing into a
		// closed connection, which would waste CPU finishing a scan nobody reads.
		select {
		case <-r.Context().Done():
			return
		default:
		}
	}
}

// Query parameter names for the /scan endpoint — kept as constants so a typo
// in either the server or a future test is caught at compile time rather than
// silently falling back to the default value at runtime.
const (
	queryParamTarget    = "target"
	queryParamPorts     = "ports"
	queryParamWorkers   = "workers"
	queryParamTimeout   = "timeout"
	queryParamRateLimit = "rate_limit"
	queryParamDB        = "db"

	// maxWorkers caps the goroutine pool size accepted from the web UI to prevent
	// resource exhaustion. The web endpoint is network-accessible, so a hard cap
	// is required. CLI users choose their own --workers value and bear the risk.
	maxWorkers = 500

	// maxScanTimeout caps the per-connection deadline accepted from the web UI.
	// An unbounded value would allow a single browser tab to hold a scan goroutine
	// open indefinitely. 30 seconds covers the slowest realistic banner grab.
	maxScanTimeout = 30 * time.Second

	// maxConcurrentScans limits the number of simultaneously active SSE scan
	// connections. Each active scan spawns a full pipeline goroutine that makes
	// outbound network requests and, when a DSN is provided, holds a database
	// connection. Without a cap, a single attacker could exhaust file descriptors
	// and memory by opening many browser tabs.
	maxConcurrentScans = 50
)

// scanSemaphore is a buffered channel used as a counting semaphore. A handler
// must acquire one slot before starting a scan and release it on return. When
// the channel is full, the next request receives a capacity-error SSE event
// instead of being queued — preventing memory growth under load.
var scanSemaphore = make(chan struct{}, maxConcurrentScans)

// isPrivateTarget reports whether target is a raw IP address that falls within
// a private, loopback, or link-local range.
//
// Why only raw IPs and not hostnames?
// Resolving a hostname inside the HTTP handler would require a DNS lookup before
// the scan even starts, adding latency and a new failure mode. More importantly,
// a hostname like "internal.corp" could resolve to a public IP on one network
// and a private IP on another — validating the resolved IP instead of the name
// would produce inconsistent behaviour depending on where the server runs.
// Blocking raw private IPs catches the most direct SSRF vectors (e.g.
// ?target=169.254.169.254) while leaving hostname targets to the discovery
// layer, which already scopes results via inScope.
func isPrivateTarget(target string) bool {
	ip := net.ParseIP(target)
	if ip == nil {
		return false // hostname — not a raw IP, allow through
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// buildConfig constructs a pipeline.Config from the HTTP request query params.
// The target has already been validated non-empty by the caller.
// Optional parameters mirror the CLI flags with the same defaults.
//
// Worker count and scan timeout are clamped to safe bounds: zero workers would
// stall the TCP scanner's goroutine pool, and an unbounded timeout could hold a
// scan goroutine open indefinitely from any browser tab that can reach port 8080.
func buildConfig(r *http.Request, target string) pipeline.Config {
	domain := pipeline.NormalizeDomain(target)
	ports := parsePorts(r.URL.Query().Get(queryParamPorts))
	workers := parseInt(r.URL.Query().Get(queryParamWorkers), 100)
	timeout := parseDuration(r.URL.Query().Get(queryParamTimeout), 2*time.Second)
	rateLimit := parseInt(r.URL.Query().Get(queryParamRateLimit), 0)
	dsn := r.URL.Query().Get(queryParamDB)

	if workers < 1 {
		workers = 1
	}
	if workers > maxWorkers {
		workers = maxWorkers
	}
	if timeout > maxScanTimeout {
		timeout = maxScanTimeout
	}

	return pipeline.Config{
		Domain:      domain,
		Ports:       ports,
		Workers:     workers,
		ScanTimeout: timeout,
		RateLimit:   rateLimit,
		DSN:         dsn,
		IsLocal:     pipeline.IsLocalTarget(domain),
	}
}

// writeSSEError sends a single SSE error event and flushes, then returns so
// the handler exits cleanly. The client receives the error in the same stream
// rather than an HTTP error status, which would prevent EventSource from
// reading it.
//
// The payload is constructed by marshalling an ErrorPayload struct — the same
// path every other event takes — so the output is guaranteed well-formed JSON
// without manual escaping.
func writeSSEError(w http.ResponseWriter, flusher http.Flusher, msg string) {
	payload, _ := json.Marshal(pipeline.ErrorPayload{Phase: "init", Message: msg})
	b, _ := json.Marshal(pipeline.ScanEvent{
		Type:    pipeline.EventError,
		Payload: payload,
	})
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", pipeline.EventError, b)
	flusher.Flush()
}

func parsePorts(s string) []int {
	if strings.TrimSpace(s) == "" {
		return pipeline.DefaultPorts
	}
	var ports []int
	seen := make(map[int]struct{})
	for _, tok := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(tok))
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return pipeline.DefaultPorts
	}
	return ports
}

func parseInt(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func parseDuration(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}
