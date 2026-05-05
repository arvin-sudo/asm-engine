// Package pipeline defines the event-driven wire contract between the scan
// engine and its consumers (CLI text formatter and SSE web handler).
//
// Every pipeline stage emits typed ScanEvents on a channel rather than writing
// formatted strings to an io.Writer. This decoupling lets the CLI consumer
// reproduce the existing terminal output while the SSE handler encodes the same
// data as streaming JSON — both driving the same underlying scan logic without
// any duplication.
package pipeline

import (
	"encoding/json"
	"fmt"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// EventType identifies which pipeline stage produced a ScanEvent and which
// payload schema to unmarshal.
type EventType string

const (
	// EventPhaseStart fires when a named pipeline phase begins.
	EventPhaseStart EventType = "phase_start"

	// EventPhaseComplete fires when a named pipeline phase finishes.
	EventPhaseComplete EventType = "phase_complete"

	// EventSubdomain fires once per hostname discovered or resolved in Phase 1.
	// Status field indicates "live", "dead", "wildcard", "ptr_live", or "ptr_dead".
	EventSubdomain EventType = "subdomain"

	// EventDNSIndicator fires once per TXT/MX service indicator found in Phase 1d.
	EventDNSIndicator EventType = "dns_indicator"

	// EventPort fires once per open port processed in Phase 2, carrying its
	// service fingerprint, vulnerabilities, and technology stack together.
	EventPort EventType = "port"

	// EventBucket fires once per cloud storage endpoint probed in Phase 3.
	EventBucket EventType = "bucket"

	// EventDiff fires once per differential change detected when --db is active.
	EventDiff EventType = "diff"

	// EventError carries a non-fatal error that would otherwise go to log.Printf.
	// Routing errors through the channel keeps the SSE handler informed without
	// requiring a separate side-channel.
	EventError EventType = "error"

	// EventDone signals that the pipeline has finished. The channel is closed
	// immediately after; consumers may range over the channel and rely on range
	// termination rather than listening for EventDone explicitly.
	EventDone EventType = "done"
)

// ScanEvent is the single envelope type emitted on the pipeline channel.
// Type selects the payload schema; Payload holds the JSON-encoded data for
// that type. Using json.RawMessage means the pipeline never re-encodes the
// payload — each stage marshals its struct once, and both the CLI formatter
// and the SSE handler unmarshal exactly what they need.
type ScanEvent struct {
	Type    EventType       `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// --- Payload types ---

// PhasePayload is the payload for EventPhaseStart and EventPhaseComplete.
// Message reproduces the human-readable line that main.go previously printed
// to io.Writer so consumeForCLI can output identical text.
type PhasePayload struct {
	Phase   string `json:"phase"`
	Message string `json:"message"`
}

// SubdomainPayload is the payload for EventSubdomain.
// Status values mirror the CLI label prefixes: "live", "dead", "wildcard",
// "ptr_live", "ptr_dead", "ptr_wildcard".
// DiffKind is set to models.ChangeNewAsset when --db is active and the domain
// was not present in the previous scan, enabling the [NEW] badge in the UI.
type SubdomainPayload struct {
	Name     string   `json:"name"`
	Source   string   `json:"source,omitempty"`
	Status   string   `json:"status"`
	IPs      []string `json:"ips,omitempty"`
	DiffKind string   `json:"diff_kind,omitempty"`
}

// DNSIndicatorPayload is the payload for EventDNSIndicator.
type DNSIndicatorPayload struct {
	Service  string `json:"service"`
	Record   string `json:"record"`
	Evidence string `json:"evidence"`
}

// PortPayload is the payload for EventPort. It bundles the port, its
// identified service, matched vulnerabilities, and detected technologies so
// the SSE consumer can render a complete port card in a single event.
// DiffKind is set to models.ChangePortOpened when the port was not recorded
// in the previous scan, enabling the [OPENED] badge in the UI.
type PortPayload struct {
	Domain          string                 `json:"domain"`
	IP              string                 `json:"ip"`
	Port            int                    `json:"port"`
	Proto           string                 `json:"proto"`
	ServiceName     string                 `json:"service_name,omitempty"`
	ServiceVersion  string                 `json:"service_version,omitempty"`
	Banner          string                 `json:"banner,omitempty"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities,omitempty"`
	Technologies    []models.Technology    `json:"technologies,omitempty"`
	DiffKind        string                 `json:"diff_kind,omitempty"`
}

// BucketPayload is the payload for EventBucket.
// Accessible drives the UI colour: true → red/public alert, false → green/private safe.
type BucketPayload struct {
	URL        string `json:"url"`
	Provider   string `json:"provider"`
	Status     int    `json:"status"`
	Accessible bool   `json:"accessible"`
}

// DiffPayload is the payload for EventDiff. Kind maps to models.ChangeKind
// string values (NEW ASSET, PORT OPENED, PORT CLOSED, VERSION CHANGE).
type DiffPayload struct {
	Kind        string `json:"kind"`
	Domain      string `json:"domain"`
	IP          string `json:"ip,omitempty"`
	Port        int    `json:"port,omitempty"`
	Proto       string `json:"proto,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	OldVersion  string `json:"old_version,omitempty"`
	NewVersion  string `json:"new_version,omitempty"`
}

// ErrorPayload is the payload for EventError.
type ErrorPayload struct {
	Phase   string `json:"phase"`
	Message string `json:"message"`
}

// DonePayload is the payload for EventDone.
type DonePayload struct {
	Summary string `json:"summary"`
}

// newEvent marshals payload to JSON and wraps it in a ScanEvent envelope.
// It panics only if payload is not JSON-serialisable — a programming error
// (all payload types are well-defined structs with no marshal-time side effects).
func newEvent(t EventType, payload any) ScanEvent {
	b, err := json.Marshal(payload)
	if err != nil {
		// Unreachable in production: every payload type marshals cleanly.
		// The panic surfaces the bug immediately during development rather than
		// silently dropping events.
		panic(fmt.Sprintf("pipeline: marshal %s payload: %v", t, err))
	}
	return ScanEvent{Type: t, Payload: json.RawMessage(b)}
}

// emit sends e on ch. It never blocks: if the channel buffer is full the
// event is dropped. The buffer (64 events) provides enough headroom for the
// Phase 1b subdomain burst; dropping a single progress event under extreme
// back-pressure is preferable to deadlocking the pipeline goroutine.
func emit(ch chan<- ScanEvent, e ScanEvent) {
	select {
	case ch <- e:
	default:
	}
}
