package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// schema is the DDL executed on every startup to ensure all required tables
// exist. CREATE TABLE IF NOT EXISTS makes every statement idempotent —
// repeated calls to migrate are no-ops on an already-initialised database.
//
// Design notes:
//
//   - TIMESTAMPTZ stores timestamps with time-zone context. TIMESTAMP WITHOUT
//     TIME ZONE would silently discard the zone offset, causing incorrect
//     comparisons when the engine runs on hosts in different time zones.
//
//   - Natural keys are used as primary keys where they are globally unique:
//     domain for assets, (asset_domain, ip, number, proto) for ports, the
//     same tuple for services (at most one service per port), and URL for
//     bucket_results (a cloud endpoint URL is globally unique).
//
//   - ON DELETE CASCADE propagates deletions: removing an asset removes its
//     ports and services automatically, keeping the database consistent
//     without requiring the caller to issue multiple deletes.
const schema = `
CREATE TABLE IF NOT EXISTS assets (
    domain     TEXT        PRIMARY KEY,
    ips        TEXT[]      NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS ports (
    asset_domain TEXT        NOT NULL REFERENCES assets(domain) ON DELETE CASCADE,
    ip           TEXT        NOT NULL,
    number       INTEGER     NOT NULL,
    proto        TEXT        NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (asset_domain, ip, number, proto)
);

CREATE TABLE IF NOT EXISTS services (
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

CREATE TABLE IF NOT EXISTS bucket_results (
    url        TEXT        PRIMARY KEY,
    domain     TEXT        NOT NULL,
    provider   TEXT        NOT NULL,
    status     INTEGER     NOT NULL,
    accessible BOOLEAN     NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL
);

-- Performance: FindPorts and FindServices filter by asset_domain alone, but the
-- composite primary key (asset_domain, ip, number, proto) does not satisfy a
-- single-column equality predicate efficiently. Without a dedicated index each
-- call performs a sequential scan of the full table.
CREATE INDEX IF NOT EXISTS idx_ports_asset_domain    ON ports(asset_domain);
CREATE INDEX IF NOT EXISTS idx_services_asset_domain ON services(asset_domain);

-- Performance: bucket queries group results by domain; an index avoids scanning
-- all bucket rows when fetching findings for a specific target.
CREATE INDEX IF NOT EXISTS idx_buckets_domain        ON bucket_results(domain);
`

// PostgresStore implements Store by persisting all ASM findings to a
// PostgreSQL database.
//
// All write operations use INSERT ... ON CONFLICT DO UPDATE (upsert) so
// running the engine against the same target on different days is safe:
// FirstSeen is written once and never overwritten; LastSeen is refreshed on
// every run. This lets callers identify assets that have disappeared (their
// LastSeen lags far behind the current date) and assets that recently appeared
// (FirstSeen is close to the current date).
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore opens a connection pool to the PostgreSQL database at dsn,
// verifies connectivity with a Ping, and runs the schema migration so all
// required tables exist before the first write.
//
// dsn is a standard libpq connection string, for example:
//
//	postgres://user:password@localhost:5432/asmdb?sslmode=disable
//
// The caller must defer store.Close() to return the connection pool to the OS.
// If NewPostgresStore returns an error the pool has already been closed
// internally — the caller must not call Close() on the returned nil pointer.
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres_store: open: %w", err)
	}

	// Ping verifies the DSN is reachable before the engine begins scanning.
	// Without this check a typo in --db would only surface at the first save
	// call, after the entire discovery and scan phase has already run.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres_store: ping: %w", err)
	}

	s := &PostgresStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres_store: %w", err)
	}
	return s, nil
}

// migrate executes the schema DDL. All statements use IF NOT EXISTS so this
// is safe to call on every startup — it only creates tables that are absent.
func (s *PostgresStore) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// Close releases the connection pool. Must be called when the store is no
// longer needed — typically via defer immediately after NewPostgresStore.
func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// SaveAsset upserts a live asset. On first discovery both timestamps are set
// to now. On subsequent runs only last_seen is updated, preserving the
// original first_seen so callers can measure how long the asset has existed.
//
// The ips column is a PostgreSQL TEXT[] array. pq.Array wraps the Go string
// slice into the driver value that lib/pq knows how to serialise for the
// array type.
func (s *PostgresStore) SaveAsset(asset models.Asset) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO assets (domain, ips, first_seen, last_seen)
		VALUES ($1, $2, $3, $3)
		ON CONFLICT (domain) DO UPDATE
		    SET ips       = EXCLUDED.ips,
		        last_seen = EXCLUDED.last_seen
	`, asset.Domain, pq.Array(asset.IPs), now)
	if err != nil {
		return fmt.Errorf("save_asset %q: %w", asset.Domain, err)
	}
	return nil
}

// SavePort upserts a single open port. The composite key
// (asset_domain, ip, number, proto) uniquely identifies a port — the same
// port number on two different IPs of the same asset produces two separate
// rows. Only last_seen is updated on conflict; first_seen is preserved.
//
// The asset referenced by domain must already exist. Call SaveAsset first
// to satisfy the foreign-key constraint on assets(domain).
func (s *PostgresStore) SavePort(domain string, port models.Port) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO ports (asset_domain, ip, number, proto, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $5)
		ON CONFLICT (asset_domain, ip, number, proto) DO UPDATE
		    SET last_seen = EXCLUDED.last_seen
	`, domain, port.IP, port.Number, port.Proto, now)
	if err != nil {
		return fmt.Errorf("save_port %s:%d: %w", port.IP, port.Number, err)
	}
	return nil
}

// SaveService upserts the service identified on an open port. When the
// service name or version changes between scans (e.g. nginx is upgraded from
// 1.18.0 to 1.24.0) the row is updated and last_seen reflects when the
// change was observed, giving a timestamp for the upgrade event.
//
// The corresponding port row must already exist. Call SavePort before
// SaveService to satisfy the foreign key on ports.
func (s *PostgresStore) SaveService(domain string, svc models.Service) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO services
		    (asset_domain, ip, port_number, proto, name, version, banner, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
		ON CONFLICT (asset_domain, ip, port_number, proto) DO UPDATE
		    SET name      = EXCLUDED.name,
		        version   = EXCLUDED.version,
		        banner    = EXCLUDED.banner,
		        last_seen = EXCLUDED.last_seen
	`, domain, svc.Port.IP, svc.Port.Number, svc.Port.Proto,
		svc.Name, svc.Version, svc.Banner, now)
	if err != nil {
		return fmt.Errorf("save_service %s:%d: %w", svc.Port.IP, svc.Port.Number, err)
	}
	return nil
}

// SaveBucket upserts a cloud storage finding. URL is the natural key — each
// cloud endpoint URL is globally unique. When a bucket's accessibility changes
// between scans (e.g. a public bucket is locked down to 403) the status and
// accessible fields are updated and last_seen is refreshed.
func (s *PostgresStore) SaveBucket(domain string, bucket models.BucketResult) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO bucket_results (url, domain, provider, status, accessible, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $6)
		ON CONFLICT (url) DO UPDATE
		    SET status     = EXCLUDED.status,
		        accessible = EXCLUDED.accessible,
		        last_seen  = EXCLUDED.last_seen
	`, bucket.URL, domain, bucket.Provider, bucket.Status, bucket.Accessible, now)
	if err != nil {
		return fmt.Errorf("save_bucket %q: %w", bucket.URL, err)
	}
	return nil
}

// FindPorts returns all ports previously stored for domain, ordered by ip then
// port number. The result gives the differential analyser a snapshot of what
// was open during the last scan so it can compute opened/closed port changes.
func (s *PostgresStore) FindPorts(domain string) ([]models.Port, error) {
	rows, err := s.db.Query(`
		SELECT ip, number, proto
		FROM   ports
		WHERE  asset_domain = $1
		ORDER  BY ip, number
	`, domain)
	if err != nil {
		return nil, fmt.Errorf("find_ports %q: %w", domain, err)
	}
	defer rows.Close()

	var ports []models.Port
	for rows.Next() {
		var p models.Port
		if err := rows.Scan(&p.IP, &p.Number, &p.Proto); err != nil {
			return nil, fmt.Errorf("find_ports scan: %w", err)
		}
		ports = append(ports, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("find_ports rows: %w", err)
	}
	return ports, nil
}

// FindServices returns all services previously stored for domain, ordered by
// ip then port number. The result gives the differential analyser the version
// history needed to detect software upgrades or downgrades between scans.
func (s *PostgresStore) FindServices(domain string) ([]models.Service, error) {
	rows, err := s.db.Query(`
		SELECT ip, port_number, proto, name, version, banner
		FROM   services
		WHERE  asset_domain = $1
		ORDER  BY ip, port_number
	`, domain)
	if err != nil {
		return nil, fmt.Errorf("find_services %q: %w", domain, err)
	}
	defer rows.Close()

	var svcs []models.Service
	for rows.Next() {
		var svc models.Service
		if err := rows.Scan(
			&svc.Port.IP, &svc.Port.Number, &svc.Port.Proto,
			&svc.Name, &svc.Version, &svc.Banner,
		); err != nil {
			return nil, fmt.Errorf("find_services scan: %w", err)
		}
		svcs = append(svcs, svc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("find_services rows: %w", err)
	}
	return svcs, nil
}

// FindAssetByDomain returns the persisted record for a single domain, or
// (nil, nil) if the domain has never been saved. Unlike FindAssets, this
// performs a targeted single-row lookup — efficient when the caller already
// knows which domain it needs without loading the full asset table.
func (s *PostgresStore) FindAssetByDomain(domain string) (*models.AssetRecord, error) {
	row := s.db.QueryRow(`
		SELECT domain, ips, first_seen, last_seen
		FROM   assets
		WHERE  domain = $1
	`, domain)

	var r models.AssetRecord
	var ips pq.StringArray
	if err := row.Scan(&r.Domain, &ips, &r.FirstSeen, &r.LastSeen); err != nil {
		// sql.ErrNoRows is not an error condition — the domain simply has not
		// been seen before. Return (nil, nil) so callers can distinguish
		// "not found" from a real database failure without inspecting errors.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("find_asset_by_domain %q: %w", domain, err)
	}
	r.IPs = []string(ips)
	return &r, nil
}

// FindAssets returns every persisted asset together with its first-seen and
// last-seen timestamps, ordered by domain name.
//
// pq.StringArray is the scanner counterpart to pq.Array used in SaveAsset —
// it reads a PostgreSQL TEXT[] column back into a Go []string.
func (s *PostgresStore) FindAssets() ([]models.AssetRecord, error) {
	rows, err := s.db.Query(`
		SELECT domain, ips, first_seen, last_seen
		FROM   assets
		ORDER  BY domain
	`)
	if err != nil {
		return nil, fmt.Errorf("find_assets: %w", err)
	}
	defer rows.Close()

	var records []models.AssetRecord
	for rows.Next() {
		var r models.AssetRecord
		var ips pq.StringArray
		if err := rows.Scan(&r.Domain, &ips, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, fmt.Errorf("find_assets scan: %w", err)
		}
		r.IPs = []string(ips)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("find_assets rows: %w", err)
	}
	return records, nil
}
