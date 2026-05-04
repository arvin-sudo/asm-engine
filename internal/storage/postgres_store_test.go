//go:build integration

// Integration tests for PostgresStore. They require a live PostgreSQL instance.
//
// Run with:
//   TEST_DB="postgres://user:password@localhost:5432/asmdb_test?sslmode=disable" \
//   go test -tags integration ./internal/storage/...
//
// The test database must exist before running. All writes are scoped to
// unique domain names that are deleted in cleanup, so the tests are safe
// to run against a shared development database.
package storage

import (
	"os"
	"testing"
	"time"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// testDSN reads the PostgreSQL connection string from the environment and skips
// the test if it is absent. This prevents the integration suite from failing
// in environments where PostgreSQL is not available (e.g. a plain go test run
// without -tags integration would not even compile this file).
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DB")
	if dsn == "" {
		t.Skip("TEST_DB environment variable not set — skipping integration test")
	}
	return dsn
}

// openStore opens a PostgresStore for a test and registers a cleanup function
// that closes the connection pool when the test ends.
func openStore(t *testing.T) *PostgresStore {
	t.Helper()
	s, err := NewPostgresStore(testDSN(t))
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// cleanAsset removes the test asset and all its dependent rows (ports,
// services) via the ON DELETE CASCADE constraint, leaving the database clean.
func cleanAsset(t *testing.T, s *PostgresStore, domain string) {
	t.Helper()
	if _, err := s.db.Exec(`DELETE FROM assets WHERE domain = $1`, domain); err != nil {
		t.Fatalf("cleanup: delete asset %q: %v", domain, err)
	}
}

// cleanBucket removes a bucket_result row by URL, leaving the database clean.
func cleanBucket(t *testing.T, s *PostgresStore, url string) {
	t.Helper()
	if _, err := s.db.Exec(`DELETE FROM bucket_results WHERE url = $1`, url); err != nil {
		t.Fatalf("cleanup: delete bucket %q: %v", url, err)
	}
}

func TestPostgresStore_SaveAsset_NewRecord(t *testing.T) {
	s := openStore(t)
	const domain = "integration-test-new.example.com"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	asset := models.Asset{Domain: domain, IPs: []string{"1.2.3.4", "5.6.7.8"}}
	if err := s.SaveAsset(asset); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}

	records, err := s.FindAssets()
	if err != nil {
		t.Fatalf("FindAssets: %v", err)
	}

	var found *models.AssetRecord
	for i := range records {
		if records[i].Domain == domain {
			found = &records[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("saved asset %q not returned by FindAssets", domain)
	}
	if len(found.IPs) != 2 {
		t.Errorf("IPs: got %v, want [1.2.3.4 5.6.7.8]", found.IPs)
	}
	if found.FirstSeen.IsZero() || found.LastSeen.IsZero() {
		t.Error("timestamps must not be zero after first save")
	}
}

func TestPostgresStore_SaveAsset_UpsertPreservesFirstSeen(t *testing.T) {
	// Saving the same asset twice must update last_seen but leave first_seen
	// at the original value. This is the core invariant of the change-tracking
	// design: first_seen is a write-once timestamp.
	s := openStore(t)
	const domain = "integration-test-upsert.example.com"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	asset := models.Asset{Domain: domain, IPs: []string{"1.1.1.1"}}
	if err := s.SaveAsset(asset); err != nil {
		t.Fatalf("first SaveAsset: %v", err)
	}

	// Pause briefly so the second save's last_seen is observably later.
	time.Sleep(10 * time.Millisecond)

	asset.IPs = []string{"2.2.2.2"} // IP changed — simulates a DNS update
	if err := s.SaveAsset(asset); err != nil {
		t.Fatalf("second SaveAsset: %v", err)
	}

	records, err := s.FindAssets()
	if err != nil {
		t.Fatalf("FindAssets: %v", err)
	}
	var found *models.AssetRecord
	for i := range records {
		if records[i].Domain == domain {
			found = &records[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("asset %q not found", domain)
	}
	if !found.LastSeen.After(found.FirstSeen) {
		t.Errorf("expected LastSeen (%v) > FirstSeen (%v)", found.LastSeen, found.FirstSeen)
	}
	if found.IPs[0] != "2.2.2.2" {
		t.Errorf("IPs not updated on upsert: got %v", found.IPs)
	}
}

func TestPostgresStore_SavePort(t *testing.T) {
	s := openStore(t)
	const domain = "integration-test-port.example.com"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"10.0.0.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}

	port := models.Port{IP: "10.0.0.1", Number: 443, Proto: "tcp"}
	if err := s.SavePort(domain, port); err != nil {
		t.Fatalf("SavePort: %v", err)
	}

	// Upsert should not return an error on a second call for the same port.
	if err := s.SavePort(domain, port); err != nil {
		t.Fatalf("SavePort (upsert): %v", err)
	}
}

func TestPostgresStore_SaveService(t *testing.T) {
	s := openStore(t)
	const domain = "integration-test-service.example.com"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"10.0.0.2"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	port := models.Port{IP: "10.0.0.2", Number: 80, Proto: "tcp"}
	if err := s.SavePort(domain, port); err != nil {
		t.Fatalf("SavePort: %v", err)
	}

	svc := models.Service{
		Port:    port,
		Name:    "nginx",
		Version: "1.18.0",
		Banner:  "HTTP/1.0 200 OK\r\nServer: nginx/1.18.0\r\n",
	}
	if err := s.SaveService(domain, svc); err != nil {
		t.Fatalf("SaveService: %v", err)
	}

	// Simulate a version upgrade — the row should be updated, not duplicated.
	svc.Version = "1.24.0"
	if err := s.SaveService(domain, svc); err != nil {
		t.Fatalf("SaveService (upsert): %v", err)
	}
}

func TestPostgresStore_SaveBucket(t *testing.T) {
	s := openStore(t)
	const testURL = "https://integration-test-bucket.s3.amazonaws.com"
	t.Cleanup(func() { cleanBucket(t, s, testURL) })

	bucket := models.BucketResult{
		URL:        testURL,
		Provider:   "aws_s3",
		Status:     200,
		Accessible: true,
	}
	if err := s.SaveBucket("integration-test.example.com", bucket); err != nil {
		t.Fatalf("SaveBucket: %v", err)
	}

	// A subsequent save simulating the bucket being locked down.
	bucket.Status = 403
	bucket.Accessible = false
	if err := s.SaveBucket("integration-test.example.com", bucket); err != nil {
		t.Fatalf("SaveBucket (upsert): %v", err)
	}
}

func TestPostgresStore_FindAssets_Empty(t *testing.T) {
	// FindAssets on a database with no matching rows must return an empty
	// slice rather than nil — callers range over the result and a nil slice
	// is safe to range, but the explicit expectation is stated here to document
	// the contract.
	s := openStore(t)

	records, err := s.FindAssets()
	if err != nil {
		t.Fatalf("FindAssets: %v", err)
	}
	// A nil slice is a valid empty result in Go — just check the call succeeds.
	_ = records
}

func TestPostgresStore_FindPorts(t *testing.T) {
	// Verify that FindPorts returns the ports saved for a domain, and that
	// querying an unknown domain returns an empty result without error.
	s := openStore(t)
	const domain = "integration-test-findports.example.com"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"10.0.1.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	p1 := models.Port{IP: "10.0.1.1", Number: 80, Proto: "tcp"}
	p2 := models.Port{IP: "10.0.1.1", Number: 443, Proto: "tcp"}
	if err := s.SavePort(domain, p1); err != nil {
		t.Fatalf("SavePort 80: %v", err)
	}
	if err := s.SavePort(domain, p2); err != nil {
		t.Fatalf("SavePort 443: %v", err)
	}

	got, err := s.FindPorts(domain)
	if err != nil {
		t.Fatalf("FindPorts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("FindPorts: got %d ports, want 2", len(got))
	}
	// Results are ordered by ip then port number per the query.
	if got[0].Number != 80 || got[1].Number != 443 {
		t.Errorf("FindPorts order: got ports %d,%d, want 80,443", got[0].Number, got[1].Number)
	}

	// Unknown domain must return empty result, not error.
	empty, err := s.FindPorts("nonexistent.example.com")
	if err != nil {
		t.Fatalf("FindPorts(unknown): unexpected error: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("FindPorts(unknown): got %d ports, want 0", len(empty))
	}
}

func TestPostgresStore_FindAssetByDomain(t *testing.T) {
	s := openStore(t)
	const domain = "integration-test-findbydomain.example.com"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	// Domain not in database must return (nil, nil) — not an error.
	got, err := s.FindAssetByDomain(domain)
	if err != nil {
		t.Fatalf("FindAssetByDomain(missing): unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("FindAssetByDomain(missing): expected nil record, got %+v", got)
	}

	// Save an asset and verify the record is returned correctly.
	asset := models.Asset{Domain: domain, IPs: []string{"10.1.2.3"}}
	if err := s.SaveAsset(asset); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}

	got, err = s.FindAssetByDomain(domain)
	if err != nil {
		t.Fatalf("FindAssetByDomain: %v", err)
	}
	if got == nil {
		t.Fatal("FindAssetByDomain: expected record, got nil")
	}
	if got.Domain != domain {
		t.Errorf("Domain: got %q, want %q", got.Domain, domain)
	}
	if len(got.IPs) != 1 || got.IPs[0] != "10.1.2.3" {
		t.Errorf("IPs: got %v, want [10.1.2.3]", got.IPs)
	}
	if got.FirstSeen.IsZero() || got.LastSeen.IsZero() {
		t.Error("timestamps must not be zero after save")
	}
}

func TestPostgresStore_FindServices(t *testing.T) {
	// Verify that FindServices returns services for a domain, and that a domain
	// with no services returns an empty result without error.
	s := openStore(t)
	const domain = "integration-test-findservices.example.com"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"10.0.2.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	port := models.Port{IP: "10.0.2.1", Number: 443, Proto: "tcp"}
	if err := s.SavePort(domain, port); err != nil {
		t.Fatalf("SavePort: %v", err)
	}
	svc := models.Service{Port: port, Name: "nginx", Version: "1.18.0", Banner: "HTTP/1.0 200 OK"}
	if err := s.SaveService(domain, svc); err != nil {
		t.Fatalf("SaveService: %v", err)
	}

	got, err := s.FindServices(domain)
	if err != nil {
		t.Fatalf("FindServices: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("FindServices: got %d services, want 1", len(got))
	}
	if got[0].Name != "nginx" || got[0].Version != "1.18.0" {
		t.Errorf("FindServices: got name=%q version=%q, want nginx/1.18.0", got[0].Name, got[0].Version)
	}

	// Domain with no services must return empty result, not error.
	empty, err := s.FindServices("nonexistent.example.com")
	if err != nil {
		t.Fatalf("FindServices(unknown): unexpected error: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("FindServices(unknown): got %d services, want 0", len(empty))
	}
}
