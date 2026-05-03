// Package models — diff.go defines the types used by the differential analysis
// stage (internal/analysis) to describe what changed between two scan runs.
//
// These types live in pkg/models rather than internal/analysis so that both
// the analysis package (which computes the diff) and cmd/asm/main.go (which
// prints it) can import them without creating an import cycle.
package models

// ChangeKind classifies the nature of a single finding change between two scan
// runs. Each constant maps to a label printed in the differential output.
type ChangeKind string

const (
	// ChangeNewAsset marks a domain that was not present in the previous scan.
	// It appears in the live-asset list today but had no record in the database
	// before this run — shadow IT, a newly provisioned host, or a record that
	// was cleaned from the DB.
	ChangeNewAsset ChangeKind = "NEW ASSET"

	// ChangePortOpened marks a port that is open now but was not recorded as
	// open in the previous scan. This may indicate a new service was deployed,
	// a firewall rule was relaxed, or a service was moved to a different port.
	ChangePortOpened ChangeKind = "PORT OPENED"

	// ChangePortClosed marks a port that was open in the previous scan but is
	// not in the current scan results. The service may have been decommissioned,
	// a firewall rule tightened, or the service is temporarily down.
	ChangePortClosed ChangeKind = "PORT CLOSED"

	// ChangeVersionChange marks a service whose reported version differs from
	// what was stored in the previous scan — an upgrade, downgrade, or
	// reconfiguration. Version changes are high-value findings because they
	// trigger a fresh vulnerability check against the new version string.
	ChangeVersionChange ChangeKind = "VERSION CHANGE"
)

// AssetChange records a domain-level change between scan runs.
type AssetChange struct {
	// Domain is the hostname that appeared or disappeared.
	Domain string

	// Kind is always ChangeNewAsset for asset-level changes; port and service
	// changes are represented by PortChange and ServiceChange respectively.
	Kind ChangeKind
}

// PortChange records a single port that was opened or closed between scans.
type PortChange struct {
	// Port is the specific (IP, number, proto) tuple that changed.
	Port Port

	// Kind is ChangePortOpened or ChangePortClosed.
	Kind ChangeKind
}

// ServiceChange records a version change for a service observed on a port.
// It is only produced when both the old and new scans identified the same
// service by name on the same port, but the reported version strings differ.
type ServiceChange struct {
	// Port identifies which (IP, port number, proto) the service runs on.
	Port Port

	// ServiceName is the software identifier (e.g. "nginx", "openssh").
	ServiceName string

	// OldVersion is the version string from the previous scan. May be empty
	// if the service was identified but no version was extracted last time.
	OldVersion string

	// NewVersion is the version string from the current scan.
	NewVersion string
}

// ScanDiff is the complete set of changes detected for one asset domain
// between the current scan run and the most recent previous run stored in the
// database. An empty ScanDiff (all slices nil or zero length) means no changes
// were detected — the attack surface is stable.
type ScanDiff struct {
	// Domain is the asset this diff pertains to.
	Domain string

	// AssetChanges lists new assets discovered (ChangeNewAsset) or
	// assets absent from the current run. Currently only new assets are
	// reported here; disappearing assets require comparing the full historical
	// asset list against the current live list, which is handled at the
	// pipeline level in main.go.
	AssetChanges []AssetChange

	// PortChanges lists ports that were opened or closed since last scan.
	PortChanges []PortChange

	// ServiceChanges lists services whose version string changed.
	ServiceChanges []ServiceChange
}

// IsEmpty reports whether the diff contains no changes of any kind.
// Used by main.go to suppress the diff output block when the attack surface
// is stable.
func (d *ScanDiff) IsEmpty() bool {
	return len(d.AssetChanges) == 0 &&
		len(d.PortChanges) == 0 &&
		len(d.ServiceChanges) == 0
}
