// Package analysis implements the differential analysis stage of the ASM pipeline.
//
// Its single responsibility is comparing the current scan results for an asset
// against the historical state stored in the database and producing a ScanDiff
// that describes what changed. No network I/O, no persistence — pure comparison
// logic that is fast, deterministic, and independently testable.
//
// Why a separate package rather than logic in main.go?
// Diff computation requires building lookup maps, comparing port sets, and
// matching service versions — non-trivial logic that would pollute main.go's
// wiring layer and be impossible to unit-test without a live database. Isolating
// it here means the algorithm can be tested with lightweight in-memory stubs.
//
// Why not import storage.Store directly?
// Depending on the concrete Store interface would mean every test needs a full
// Store implementation. The HistoryReader interface is a narrow read-only subset
// of Store (Interface Segregation), which keeps the test mock minimal.
package analysis

import (
	"fmt"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// HistoryReader is the read-only subset of storage.Store required by Differ.
//
// Narrowing the dependency to just the two query methods means test mocks
// only need to implement two functions — not the full Store interface.
// storage.PostgresStore satisfies this interface automatically because it
// implements all Store methods, which includes these three.
type HistoryReader interface {
	// FindPorts returns all ports recorded for the given asset domain in the
	// most recent scan stored in the database.
	FindPorts(domain string) ([]models.Port, error)

	// FindServices returns all services recorded for the given asset domain in
	// the most recent scan stored in the database.
	FindServices(domain string) ([]models.Service, error)

	// FindAssets returns all asset records in the database. Used to detect
	// new assets by comparing the current live list against historical records.
	FindAssets() ([]models.AssetRecord, error)
}

// portKey uniquely identifies a port within an asset across multiple IPs.
// Used as a map key in DiffAsset to build port and service lookup sets
// without allocating separate composite-key strings.
type portKey struct {
	ip     string
	number int
	proto  string
}

// Differ computes the difference between the current scan results and the last
// known state stored in the database.
type Differ struct {
	reader HistoryReader
}

// NewDiffer constructs a Differ backed by the provided HistoryReader.
// In production, pass the *storage.PostgresStore directly — it satisfies
// HistoryReader. In tests, pass a mockHistoryReader.
func NewDiffer(r HistoryReader) *Differ {
	return &Differ{reader: r}
}

// LoadAssetHistory fetches the last-known ports and services for domain from
// the backing store and returns them as a single snapshot.
//
// Call this before writing any new scan results for the asset so the returned
// snapshot reflects the pre-scan database state. This is the correct timing:
// once SavePort or SaveService has run, the database rows contain the current
// scan's data and a subsequent FindServices call would compare new vs new —
// producing no version-change events even when a version did change.
//
// The returned *models.AssetHistory is passed directly to DiffAsset, keeping
// the snapshot lifetime explicit and visible at the call site in main.go.
func (d *Differ) LoadAssetHistory(domain string) (*models.AssetHistory, error) {
	ports, err := d.reader.FindPorts(domain)
	if err != nil {
		return nil, fmt.Errorf("differ: find ports %q: %w", domain, err)
	}
	svcs, err := d.reader.FindServices(domain)
	if err != nil {
		return nil, fmt.Errorf("differ: find services %q: %w", domain, err)
	}
	return &models.AssetHistory{Ports: ports, Services: svcs}, nil
}

// DiffAssets compares the current list of live assets against all records in
// the database and returns a ScanDiff listing new assets (domains present in
// current but not in the database).
//
// The domain field of the returned ScanDiff is empty because this diff spans
// multiple domains. Callers combine the result with per-asset diffs from
// DiffAsset when printing the full differential summary.
func (d *Differ) DiffAssets(current []models.Asset) (*models.ScanDiff, error) {
	historical, err := d.reader.FindAssets()
	if err != nil {
		return nil, fmt.Errorf("differ: find assets: %w", err)
	}

	// Build a set of previously-known domain names for O(1) lookup.
	known := make(map[string]struct{}, len(historical))
	for _, r := range historical {
		known[r.Domain] = struct{}{}
	}

	diff := &models.ScanDiff{}
	for _, a := range current {
		if _, ok := known[a.Domain]; !ok {
			diff.AssetChanges = append(diff.AssetChanges, models.AssetChange{
				Domain: a.Domain,
				Kind:   models.ChangeNewAsset,
			})
		}
	}
	return diff, nil
}

// DiffAsset compares the current scan results for a single asset domain against
// the historical snapshot and returns a ScanDiff describing which ports were
// opened or closed and which service versions changed.
//
// This is a pure function: it performs no database reads and returns no error.
// All historical state comes from history, which must be loaded via
// LoadAssetHistory before any current-scan results are saved to the database.
//
// Rules:
//   - A port present in current but not in history → ChangePortOpened
//   - A port present in history but not in current → ChangePortClosed
//   - A service present in both scans with a different non-empty version → ChangeVersionChange
func (d *Differ) DiffAsset(domain string, history *models.AssetHistory, currentPorts []models.Port, currentServices []models.Service) *models.ScanDiff {
	diff := &models.ScanDiff{Domain: domain}

	histPortSet := make(map[portKey]struct{}, len(history.Ports))
	for _, p := range history.Ports {
		histPortSet[portKey{p.IP, p.Number, p.Proto}] = struct{}{}
	}

	currPortSet := make(map[portKey]struct{}, len(currentPorts))
	for _, p := range currentPorts {
		currPortSet[portKey{p.IP, p.Number, p.Proto}] = struct{}{}
	}

	for _, p := range currentPorts {
		if _, ok := histPortSet[portKey{p.IP, p.Number, p.Proto}]; !ok {
			diff.PortChanges = append(diff.PortChanges, models.PortChange{
				Port: p,
				Kind: models.ChangePortOpened,
			})
		}
	}

	for _, p := range history.Ports {
		if _, ok := currPortSet[portKey{p.IP, p.Number, p.Proto}]; !ok {
			diff.PortChanges = append(diff.PortChanges, models.PortChange{
				Port: p,
				Kind: models.ChangePortClosed,
			})
		}
	}

	// --- Service version diff ---
	// Build a map of historical services keyed by (ip, port number, proto).
	// portKey is reused here: a service is uniquely located by its port
	// coordinates, so the same identity struct covers both lookups.
	histSvcMap := make(map[portKey]models.Service, len(history.Services))
	for _, s := range history.Services {
		histSvcMap[portKey{s.Port.IP, s.Port.Number, s.Port.Proto}] = s
	}

	for _, curr := range currentServices {
		hist, ok := histSvcMap[portKey{curr.Port.IP, curr.Port.Number, curr.Port.Proto}]
		if !ok {
			// New service on a newly-opened port — already covered by PortChange.
			continue
		}
		// Only report a version change when both scans produced a non-empty
		// version string. An empty-to-non-empty transition is not meaningful
		// enough to report — it could just be that fingerprinting succeeded
		// this time where it failed last time.
		if curr.Version != "" && hist.Version != "" && curr.Version != hist.Version {
			diff.ServiceChanges = append(diff.ServiceChanges, models.ServiceChange{
				Port:        curr.Port,
				ServiceName: curr.Name,
				OldVersion:  hist.Version,
				NewVersion:  curr.Version,
			})
		}
	}

	return diff
}
