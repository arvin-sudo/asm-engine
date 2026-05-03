// Package storage defines the interface and PostgreSQL implementation for
// Phase 4 of the ASM pipeline: persisting every finding to a durable store
// and enabling change detection across scan runs.
//
// The rest of the engine is completely decoupled from the database by the
// Store interface. cmd/asm/main.go wires in the PostgreSQL implementation when
// --db is supplied; when the flag is absent it holds a nil Store and all save
// calls are skipped. Unit tests can inject an in-memory stub without a real
// database.
//
// Why PostgreSQL? The upsert semantics (INSERT ... ON CONFLICT DO UPDATE)
// make it straightforward to implement the FirstSeen/LastSeen pattern without
// a read-modify-write cycle. The TIMESTAMPTZ column type stores timestamps
// with time-zone information, which prevents silent data loss when the engine
// runs on hosts in different time zones.
package storage

import "github.com/arvin-sudo/asm-engine/pkg/models"

// Store is the contract for persisting and querying ASM findings.
//
// Every write method uses upsert semantics: a finding that already exists has
// its LastSeen timestamp updated to now; a new finding is created with both
// FirstSeen and LastSeen set to now. This makes every scan run additive —
// running the engine twice against the same target produces one record per
// finding, not two.
//
// The interface is ordered by pipeline stage. Callers must respect the
// dependency order when writing: SaveAsset before SavePort, SavePort before
// SaveService. This reflects the foreign-key constraints in the schema —
// a port record references its asset, and a service record references its port.
type Store interface {
	// SaveAsset upserts a live, resolved host. Domain is the natural key.
	// On first discovery both FirstSeen and LastSeen are set to now.
	// On subsequent runs only LastSeen is updated, preserving the original
	// discovery timestamp.
	SaveAsset(asset models.Asset) error

	// SavePort upserts a single open port discovered on an asset.
	// The (asset_domain, ip, number, proto) tuple is the natural key.
	// domain must already exist in the store — call SaveAsset first.
	SavePort(domain string, port models.Port) error

	// SaveService upserts the service identified on an open port.
	// The (asset_domain, ip, port_number, proto) tuple is the natural key.
	// When a service name or version changes between scans the row is updated
	// and LastSeen reflects when the change was observed.
	// The corresponding port must already exist — call SavePort first.
	SaveService(domain string, svc models.Service) error

	// SaveBucket upserts a cloud storage finding. URL is the natural key.
	// When a bucket's accessibility changes between scans (e.g. a public
	// bucket is locked down) the status and accessible fields are updated.
	SaveBucket(domain string, bucket models.BucketResult) error

	// FindAssets returns every persisted asset together with its first-seen
	// and last-seen timestamps. Results are ordered by domain name.
	// A large gap between LastSeen and the current time indicates the asset
	// may have disappeared from the attack surface since the last scan.
	FindAssets() ([]models.AssetRecord, error)

	// FindPorts returns all ports previously observed for the given asset domain,
	// ordered by ip then port number. Used by the differential analyser to
	// compare the current scan's open ports against the last known state.
	FindPorts(domain string) ([]models.Port, error)

	// FindServices returns all services previously observed for the given asset
	// domain, ordered by ip then port number. Used by the differential analyser
	// to detect version changes between scan runs.
	FindServices(domain string) ([]models.Service, error)

	// Close releases any resources held by the store, such as a database
	// connection pool. Callers must defer Close immediately after a successful
	// NewPostgresStore call.
	Close() error
}
