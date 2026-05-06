package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arvin-sudo/asm-engine/internal/pipeline"
)

// ---------------------------------------------------------------------------
// parsePorts
// ---------------------------------------------------------------------------

func TestParsePorts_EmptyReturnsDefaults(t *testing.T) {
	got := parsePorts("")
	if len(got) != len(pipeline.DefaultPorts) {
		t.Errorf("parsePorts(\"\") returned %d ports, want %d (DefaultPorts)", len(got), len(pipeline.DefaultPorts))
	}
}

func TestParsePorts_AllInvalidTokensFallBackToDefaults(t *testing.T) {
	// When every token fails validation the function falls back to DefaultPorts
	// rather than returning an empty slice — same behaviour as the empty string.
	got := parsePorts("0,99999,abc")
	if len(got) != len(pipeline.DefaultPorts) {
		t.Errorf("parsePorts(all-invalid) returned %d ports, want %d (DefaultPorts)", len(got), len(pipeline.DefaultPorts))
	}
}

func TestParsePorts_ValidInput(t *testing.T) {
	tests := []struct {
		input string
		want  []int
	}{
		{"80", []int{80}},
		{"80,443", []int{80, 443}},
		{"80, 443", []int{80, 443}},    // whitespace trimmed
		{"80,80,443", []int{80, 443}},  // duplicate dropped
		{"1,65535", []int{1, 65535}},   // boundary values accepted
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parsePorts(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("parsePorts(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ports[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseInt
// ---------------------------------------------------------------------------

func TestParseInt(t *testing.T) {
	tests := []struct {
		name  string
		input string
		def   int
		want  int
	}{
		{"empty string returns default", "", 100, 100},
		{"valid positive", "50", 100, 50},
		{"zero passes through", "0", 100, 0},
		{"negative returns default", "-1", 100, 100},
		{"non-integer returns default", "abc", 100, 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseInt(tt.input, tt.def)
			if got != tt.want {
				t.Errorf("parseInt(%q, %d) = %d, want %d", tt.input, tt.def, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseDuration
// ---------------------------------------------------------------------------

func TestParseDuration(t *testing.T) {
	def := 2 * time.Second
	tests := []struct {
		name  string
		input string
		want  time.Duration
	}{
		{"empty string returns default", "", def},
		{"valid duration", "5s", 5 * time.Second},
		{"valid milliseconds", "500ms", 500 * time.Millisecond},
		{"invalid string returns default", "notaduration", def},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDuration(tt.input, def)
			if got != tt.want {
				t.Errorf("parseDuration(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildConfig
// ---------------------------------------------------------------------------

func TestBuildConfig_Defaults(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scan?target=Example.Com.", nil)
	cfg := buildConfig(req, "Example.Com.")

	// Target must be lowercased and trailing dot stripped.
	if cfg.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", cfg.Domain, "example.com")
	}
	// Default workers when param absent.
	if cfg.Workers != 100 {
		t.Errorf("Workers = %d, want 100", cfg.Workers)
	}
	// Default timeout when param absent.
	if cfg.ScanTimeout != 2*time.Second {
		t.Errorf("ScanTimeout = %v, want 2s", cfg.ScanTimeout)
	}
}

func TestBuildConfig_IsLocalForBareHostname(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scan?target=victim-service", nil)
	cfg := buildConfig(req, "victim-service")
	if !cfg.IsLocal {
		t.Error("IsLocal = false for bare hostname, want true")
	}
}

func TestBuildConfig_IsLocalForIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scan?target=192.168.1.1", nil)
	cfg := buildConfig(req, "192.168.1.1")
	if !cfg.IsLocal {
		t.Error("IsLocal = false for IP address, want true")
	}
}

// ---------------------------------------------------------------------------
// serveIndex
// ---------------------------------------------------------------------------

func TestServeIndex_RootPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	serveIndex(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
	if rr.Body.Len() == 0 {
		t.Error("response body is empty, want embedded HTML")
	}
}

func TestServeIndex_NonRootPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	rr := httptest.NewRecorder()
	serveIndex(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// handleScan — missing target
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// handleScan — happy path
// ---------------------------------------------------------------------------

// TestHandleScan_ValidScan verifies that handleScan sets the correct SSE
// headers and that pipeline events are forwarded to the response body.
//
// A pre-cancelled context keeps the test instant and network-free. The
// execute() goroutine still emits the Phase 1 completion event (OSINT skipped
// for local targets) before it checks ctx.Err() and exits — giving us a real,
// pipeline-produced SSE event to assert on without running a full scan.
func TestHandleScan_ValidScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulate immediate cancellation / disconnect

	req := httptest.NewRequest(http.MethodGet, "/scan?target=127.0.0.1", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handleScan(rr, req)

	// SSE content-type must be set before any body bytes are written.
	if ct := rr.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	// The pipeline always emits phase_complete for the OSINT-skip before the
	// first ctx.Err() check; verify it reached the response body.
	if body := rr.Body.String(); !strings.Contains(body, "event: "+string(pipeline.EventPhaseComplete)) {
		t.Errorf("response body does not contain phase_complete event; got:\n%s", body)
	}
}

// TestHandleScan_ClientDisconnect verifies that handleScan exits cleanly when
// the client disconnects (context cancelled) before the scan completes.
//
// A pre-cancelled context simulates an immediate disconnect. The pipeline
// goroutine must detect the cancellation and close the event channel so the
// range loop in handleScan terminates without blocking or panicking.
func TestHandleScan_ClientDisconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // disconnect immediately

	req := httptest.NewRequest(http.MethodGet,
		"/scan?target=127.0.0.1&"+queryParamPorts+"=19998&"+queryParamTimeout+"=50ms", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	// The handler must return without blocking or panicking.
	handleScan(rr, req)
}

// ---------------------------------------------------------------------------
// handleScan — missing target
// ---------------------------------------------------------------------------

func TestHandleScan_MissingTarget(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scan", nil)
	// httptest.ResponseRecorder implements http.Flusher so handleScan can write
	// SSE events and call Flush without panicking.
	rr := httptest.NewRecorder()
	handleScan(rr, req)

	body := rr.Body.String()
	// The handler must send an SSE error event, not an HTTP error status.
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (SSE error is in the body, not the status line)", rr.Code)
	}
	if !strings.Contains(body, "event: error") {
		t.Errorf("response body does not contain SSE error event; got:\n%s", body)
	}
	if !strings.Contains(body, "target") {
		t.Errorf("error payload does not mention 'target'; got:\n%s", body)
	}
}
