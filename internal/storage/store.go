// Package storage defines the interface for Phase 4 of the ASM pipeline:
// persisting discovered assets to a durable data store.
//
// The rest of the engine is completely decoupled from the database technology
// by this interface. In Phase 4 we will wire in a PostgreSQL implementation
// that tracks when each asset was first and last seen, enabling change
// detection over time. For unit tests, an in-memory implementation can be
// supplied instead. Neither choice requires touching any other package.
package storage

import "github.com/arvin-sudo/asm-engine/pkg/models"

// Store is the contract for reading and writing discovered assets.
//
// The interface is intentionally minimal at this stage — it defines only the
// operations we need right now. It will be extended in Phase 4 to support
// subdomain persistence, change tracking (FirstSeen / LastSeen), and filtered
// queries. Adding methods to an interface is a breaking change in Go, so we
// grow it deliberately rather than front-loading every possible database
// operation up front.
type Store interface {
	// Save persists asset to the backing store. If an asset with the same
	// domain already exists, the implementation should update it (upsert)
	// rather than creating a duplicate. Callers are expected to pass only
	// valid assets (asset.IsValid() == true).
	Save(asset models.Asset) error

	// FindAll returns every asset previously stored. The order of the returned
	// slice is implementation-defined and should not be relied upon by callers.
	FindAll() ([]models.Asset, error)
}
