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
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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

	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		writeSSEError(w, flusher, "target query parameter is required")
		return
	}

	cfg := buildConfig(r, target)
	runner, err := pipeline.NewRunner(cfg)
	if err != nil {
		writeSSEError(w, flusher, err.Error())
		return
	}
	defer runner.Close()

	// r.Context() is cancelled automatically by Go's HTTP server when the
	// client closes the tab or connection. Passing it to Run propagates the
	// cancellation into the pipeline goroutine so it exits cleanly.
	for e := range runner.Run(r.Context(), cfg) {
		b, err := json.Marshal(e)
		if err != nil {
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

// buildConfig constructs a pipeline.Config from the HTTP request query params.
// The target has already been validated non-empty by the caller.
// Optional parameters mirror the CLI flags with the same defaults.
func buildConfig(r *http.Request, target string) pipeline.Config {
	ports := parsePorts(r.URL.Query().Get("ports"))
	workers := parseInt(r.URL.Query().Get("workers"), 100)
	timeout := parseDuration(r.URL.Query().Get("timeout"), 2*time.Second)
	rateLimit := parseInt(r.URL.Query().Get("rate_limit"), 0)
	dsn := r.URL.Query().Get("db")

	return pipeline.Config{
		Domain:      strings.ToLower(strings.TrimRight(target, ".")),
		Ports:       ports,
		Workers:     workers,
		ScanTimeout: timeout,
		RateLimit:   rateLimit,
		DSN:         dsn,
		IsLocal:     pipeline.IsLocalTarget(strings.ToLower(strings.TrimRight(target, "."))),
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
	fmt.Fprintf(w, "event: error\ndata: %s\n\n", b)
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
