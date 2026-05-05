// Tests for pure pipeline functions and the Runner event contract.
//
// Because tests live in package pipeline (not package pipeline_test), they can
// construct Runner structs directly with injected mocks — no exported
// constructor overloads required.
package pipeline

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// ---------------------------------------------------------------------------
// Minimal mock implementations of the interfaces Runner depends on.
// Each mock is defined inline here — they are test artefacts only.
// ---------------------------------------------------------------------------

type mockSubdomainDiscoverer struct {
	results []models.Subdomain
	err     error
}

func (m mockSubdomainDiscoverer) Discover(_ string) ([]models.Subdomain, error) {
	return m.results, m.err
}

type mockDiscoverer struct {
	asset models.Asset
	err   error
}

func (m mockDiscoverer) Discover(_ string) (models.Asset, error) {
	return m.asset, m.err
}

type mockScanner struct {
	ports []models.Port
	err   error
}

func (m mockScanner) Scan(_ models.Asset) ([]models.Port, error) {
	return m.ports, m.err
}

type mockFingerprinter struct{}

func (m mockFingerprinter) Fingerprint(p models.Port) (models.Service, error) {
	return models.Service{Port: p}, nil
}

type mockWebFP struct{}

func (m mockWebFP) FingerprintWeb(_ string, _ models.Port) ([]models.Technology, error) {
	return nil, nil
}
func (m mockWebFP) CanFingerprint(_ int) bool { return false }

type mockVulnChecker struct{}

func (m mockVulnChecker) Check(_, _ string) []models.Vulnerability { return nil }

type mockCloudScanner struct {
	results []models.BucketResult
	err     error
}

func (m mockCloudScanner) Scan(_ string) ([]models.BucketResult, error) {
	return m.results, m.err
}

// buildTestRunner constructs a Runner with all fields populated by the mocks
// above so execute() never hits a nil dereference. ptrEnricher and
// intelScanner are omitted intentionally — they are only called from
// runPhase1, which is bypassed when Config.IsLocal is true.
func buildTestRunner() *Runner {
	return &Runner{
		tcpScanner:   mockScanner{},
		bannerFP:     mockFingerprinter{},
		webFP:        mockWebFP{},
		vulnChecker:  mockVulnChecker{},
		cloudScanner: mockCloudScanner{},
	}
}

// collectEvents drains the channel and returns all received events. It blocks
// until the channel is closed so tests can assert on the complete sequence.
func collectEvents(ch <-chan ScanEvent) []ScanEvent {
	var events []ScanEvent
	for e := range ch {
		events = append(events, e)
	}
	return events
}

// ---------------------------------------------------------------------------
// TestIsLocalTarget
// ---------------------------------------------------------------------------

func TestIsLocalTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"IP v4 address", "192.168.1.1", true},
		{"IP v6 address", "::1", true},
		{"bare hostname (no dots)", "victim-service", true},
		{"dotted domain", "example.com", false},
		{"subdomain", "api.example.com", false},
		{"empty string", "", true}, // no dot → local
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLocalTarget(tt.target); got != tt.want {
				t.Errorf("IsLocalTarget(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildSyntheticAsset
// ---------------------------------------------------------------------------

func TestBuildSyntheticAsset_IPAddress(t *testing.T) {
	// For a bare IP address, Domain and IPs[0] must both equal the IP itself —
	// no DNS lookup is attempted, no external network required.
	asset := buildSyntheticAsset("1.2.3.4")
	if asset.Domain != "1.2.3.4" {
		t.Errorf("Domain = %q, want %q", asset.Domain, "1.2.3.4")
	}
	if len(asset.IPs) == 0 || asset.IPs[0] != "1.2.3.4" {
		t.Errorf("IPs = %v, want [1.2.3.4]", asset.IPs)
	}
}

func TestBuildSyntheticAsset_IPv6(t *testing.T) {
	asset := buildSyntheticAsset("::1")
	if asset.Domain != "::1" {
		t.Errorf("Domain = %q, want %q", asset.Domain, "::1")
	}
	if len(asset.IPs) == 0 || asset.IPs[0] != "::1" {
		t.Errorf("IPs = %v, want [::1]", asset.IPs)
	}
}

// ---------------------------------------------------------------------------
// TestEmit — channel send and drop behaviour
// ---------------------------------------------------------------------------

func TestEmit_SendsOnBufferedChannel(t *testing.T) {
	ch := make(chan ScanEvent, 1)
	e := newEvent(EventDone, DonePayload{Summary: "ok"})
	emit(ch, e)
	select {
	case got := <-ch:
		if got.Type != EventDone {
			t.Errorf("event type = %q, want %q", got.Type, EventDone)
		}
	default:
		t.Fatal("emit() did not send event on buffered channel")
	}
}

func TestEmit_DropsWhenChannelFull(t *testing.T) {
	// A zero-capacity channel is always full. emit must not block or panic.
	ch := make(chan ScanEvent, 0)
	e := newEvent(EventDone, DonePayload{Summary: "dropped"})
	done := make(chan struct{})
	go func() {
		emit(ch, e) // must return immediately via the default branch
		close(done)
	}()
	select {
	case <-done:
		// passed: emit returned without blocking
	case <-time.After(time.Second):
		t.Fatal("emit() blocked on a full channel (deadlock)")
	}
}

// ---------------------------------------------------------------------------
// TestNewEvent — payload marshalling
// ---------------------------------------------------------------------------

func TestNewEvent_AllPayloadTypes(t *testing.T) {
	// Every payload struct must marshal cleanly — newEvent panics otherwise.
	// This test exercises each concrete payload type to catch regressions if a
	// field type is changed to something that json.Marshal cannot handle.
	tests := []struct {
		name    string
		evtType EventType
		payload any
	}{
		{"PhasePayload start", EventPhaseStart, PhasePayload{Phase: "1a", Message: "starting"}},
		{"PhasePayload complete", EventPhaseComplete, PhasePayload{Phase: "1a", Message: "done"}},
		{"SubdomainPayload", EventSubdomain, SubdomainPayload{Name: "api.example.com", Status: "live", IPs: []string{"1.2.3.4"}}},
		{"DNSIndicatorPayload", EventDNSIndicator, DNSIndicatorPayload{Service: "gsuite", Record: "MX", Evidence: "aspmx.l.google.com"}},
		{"PortPayload", EventPort, PortPayload{Domain: "example.com", IP: "1.2.3.4", Port: 443, Proto: "tcp"}},
		{"BucketPayload", EventBucket, BucketPayload{URL: "https://example.s3.amazonaws.com", Provider: "aws_s3", Status: 200, Accessible: true}},
		{"DiffPayload", EventDiff, DiffPayload{Kind: "NEW ASSET", Domain: "new.example.com"}},
		{"ErrorPayload", EventError, ErrorPayload{Phase: "1a", Message: "timeout"}},
		{"DonePayload", EventDone, DonePayload{Summary: "scan complete"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// newEvent panics on marshal failure — the test harness catches it.
			e := newEvent(tt.evtType, tt.payload)
			if e.Type != tt.evtType {
				t.Errorf("event.Type = %q, want %q", e.Type, tt.evtType)
			}
			// Payload must be valid JSON.
			if !json.Valid(e.Payload) {
				t.Errorf("payload is not valid JSON: %s", e.Payload)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestRun_LocalTarget — full Run with IsLocal=true
// ---------------------------------------------------------------------------

func TestRun_LocalTarget(t *testing.T) {
	// IsLocal=true skips all OSINT phases, so ptrEnricher and intelScanner
	// are never called — the test runner leaves them nil.
	r := buildTestRunner()
	cfg := Config{
		Domain:      "127.0.0.1",
		Ports:       []int{80},
		Workers:     1,
		ScanTimeout: 100 * time.Millisecond,
		IsLocal:     true,
	}

	events := collectEvents(r.Run(context.Background(), cfg))

	// At minimum: phase_complete (OSINT skipped), phase_start+complete for
	// phase 2, phase_start+complete for phase 3, and done.
	if len(events) == 0 {
		t.Fatal("Run() emitted no events")
	}

	lastType := events[len(events)-1].Type
	if lastType != EventDone {
		t.Errorf("last event type = %q, want %q", lastType, EventDone)
	}
}

// ---------------------------------------------------------------------------
// TestRun_ContextCancellation — cancelled ctx stops the pipeline promptly
// ---------------------------------------------------------------------------

func TestRun_ContextCancellation(t *testing.T) {
	r := buildTestRunner()
	cfg := Config{
		Domain:      "127.0.0.1",
		Ports:       []int{80},
		Workers:     1,
		ScanTimeout: 100 * time.Millisecond,
		IsLocal:     true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run so the pipeline exits at the first ctx check

	done := make(chan struct{})
	go func() {
		// Drain channel fully — Run must close it even on early exit.
		for range r.Run(ctx, cfg) {
		}
		close(done)
	}()

	select {
	case <-done:
		// Channel closed cleanly — no goroutine leak.
	case <-time.After(5 * time.Second):
		t.Fatal("Run() goroutine did not exit after context cancellation")
	}
}
