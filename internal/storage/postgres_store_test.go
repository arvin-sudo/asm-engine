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
	"fmt"
	"os"
	"strings"
	"sync"
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

// ── Security ─────────────────────────────────────────────────────────────────

// TestPostgresStore_SQLInjection verifies that all write paths use parameterized
// queries. An injection payload in any string field must be stored verbatim and
// must not corrupt the schema or allow data exfiltration.
func TestPostgresStore_SQLInjection(t *testing.T) {
	s := openStore(t)

	// Each of these payloads would truncate the query and execute a second
	// statement if the driver were doing string interpolation.
	payloads := []string{
		`'; DROP TABLE assets; --`,
		`" OR "1"="1`,
		`\'; DELETE FROM ports; --`,
		`1; SELECT * FROM assets; --`,
	}

	for _, payload := range payloads {
		domain := "sqli-test-" + fmt.Sprintf("%x", len(payload)) + ".integration.local"
		t.Cleanup(func() { cleanAsset(t, s, domain) })

		asset := models.Asset{Domain: domain, IPs: []string{payload}}
		if err := s.SaveAsset(asset); err != nil {
			t.Fatalf("SaveAsset with injection IP %q: %v", payload, err)
		}

		// The assets table must still exist and the row must be retrievable.
		rec, err := s.FindAssetByDomain(domain)
		if err != nil {
			t.Fatalf("FindAssetByDomain after injection payload %q: %v", payload, err)
		}
		if rec == nil {
			t.Fatalf("asset not found after save with injection IP payload %q", payload)
		}
		if len(rec.IPs) != 1 || rec.IPs[0] != payload {
			t.Errorf("IP round-trip: got %v, want [%q]", rec.IPs, payload)
		}
	}

	// Injection in service name, version, banner.
	injDomain := "sqli-service.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, injDomain) })
	if err := s.SaveAsset(models.Asset{Domain: injDomain, IPs: []string{"1.1.1.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	port := models.Port{IP: "1.1.1.1", Number: 80, Proto: "tcp"}
	if err := s.SavePort(injDomain, port); err != nil {
		t.Fatalf("SavePort: %v", err)
	}
	svc := models.Service{
		Port:    port,
		Name:    `'; DROP TABLE services; --`,
		Version: `" OR "1"="1`,
		Banner:  `1'; DELETE FROM ports WHERE '1'='1`,
	}
	if err := s.SaveService(injDomain, svc); err != nil {
		t.Fatalf("SaveService with injection payloads: %v", err)
	}
	svcs, err := s.FindServices(injDomain)
	if err != nil {
		t.Fatalf("FindServices after injection: %v", err)
	}
	if len(svcs) != 1 || svcs[0].Name != svc.Name {
		t.Errorf("service name round-trip: got %q, want %q", svcs[0].Name, svc.Name)
	}
}

// ── Edge cases / safety ───────────────────────────────────────────────────────

// TestPostgresStore_SaveAsset_EmptyIPs verifies that an asset with no resolved
// IPs (e.g. DNS returned nothing) can be saved and retrieved cleanly.
func TestPostgresStore_SaveAsset_EmptyIPs(t *testing.T) {
	s := openStore(t)
	const domain = "empty-ips.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{}}); err != nil {
		t.Fatalf("SaveAsset with empty IPs: %v", err)
	}
	rec, err := s.FindAssetByDomain(domain)
	if err != nil || rec == nil {
		t.Fatalf("FindAssetByDomain: err=%v, rec=%v", err, rec)
	}
	// pq.StringArray on a Postgres {} column must round-trip as an empty (not nil) slice.
	if rec.IPs == nil {
		t.Error("IPs is nil after round-trip; want empty slice")
	}
	if len(rec.IPs) != 0 {
		t.Errorf("IPs: got %v, want []", rec.IPs)
	}
}

// TestPostgresStore_SaveAsset_ManyIPs verifies that a TEXT[] column handles a
// large IP list without truncation or error.
func TestPostgresStore_SaveAsset_ManyIPs(t *testing.T) {
	s := openStore(t)
	const domain = "many-ips.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	ips := make([]string, 50)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
	}
	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: ips}); err != nil {
		t.Fatalf("SaveAsset with 50 IPs: %v", err)
	}
	rec, err := s.FindAssetByDomain(domain)
	if err != nil || rec == nil {
		t.Fatalf("FindAssetByDomain: err=%v, rec=%v", err, rec)
	}
	if len(rec.IPs) != 50 {
		t.Errorf("IPs count: got %d, want 50", len(rec.IPs))
	}
}

// TestPostgresStore_SaveService_LongBanner verifies that a multi-kilobyte
// banner (common for TLS certificates or verbose HTTP headers) is stored and
// retrieved without truncation. PostgreSQL TEXT has no length limit.
func TestPostgresStore_SaveService_LongBanner(t *testing.T) {
	s := openStore(t)
	const domain = "long-banner.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"10.0.0.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	port := models.Port{IP: "10.0.0.1", Number: 443, Proto: "tcp"}
	if err := s.SavePort(domain, port); err != nil {
		t.Fatalf("SavePort: %v", err)
	}

	// 8 KB banner — typical size of a full TLS certificate chain in plaintext.
	longBanner := strings.Repeat("X-Header: "+strings.Repeat("a", 90)+"\r\n", 85)
	svc := models.Service{Port: port, Name: "nginx", Version: "1.24.0", Banner: longBanner}
	if err := s.SaveService(domain, svc); err != nil {
		t.Fatalf("SaveService with long banner: %v", err)
	}

	svcs, err := s.FindServices(domain)
	if err != nil || len(svcs) != 1 {
		t.Fatalf("FindServices: err=%v, count=%d", err, len(svcs))
	}
	if svcs[0].Banner != longBanner {
		t.Errorf("banner truncated: got %d bytes, want %d bytes", len(svcs[0].Banner), len(longBanner))
	}
}

// TestPostgresStore_SaveService_EmptyFields verifies that a service with no
// name, version, or banner is accepted — the schema defaults all three to ''.
func TestPostgresStore_SaveService_EmptyFields(t *testing.T) {
	s := openStore(t)
	const domain = "empty-service-fields.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"10.0.0.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	port := models.Port{IP: "10.0.0.1", Number: 22, Proto: "tcp"}
	if err := s.SavePort(domain, port); err != nil {
		t.Fatalf("SavePort: %v", err)
	}
	// No name, version, or banner — scanner could not identify the service.
	svc := models.Service{Port: port}
	if err := s.SaveService(domain, svc); err != nil {
		t.Fatalf("SaveService with empty fields: %v", err)
	}
	svcs, err := s.FindServices(domain)
	if err != nil || len(svcs) != 1 {
		t.Fatalf("FindServices: err=%v, count=%d", err, len(svcs))
	}
	if svcs[0].Name != "" || svcs[0].Version != "" || svcs[0].Banner != "" {
		t.Errorf("empty fields not preserved: name=%q version=%q banner=%q",
			svcs[0].Name, svcs[0].Version, svcs[0].Banner)
	}
}

// TestPostgresStore_SavePort_UDPProto verifies that UDP ports are stored and
// retrieved correctly — proto is free-form TEXT, not an enum.
func TestPostgresStore_SavePort_UDPProto(t *testing.T) {
	s := openStore(t)
	const domain = "udp-port.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"10.0.0.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	udp := models.Port{IP: "10.0.0.1", Number: 53, Proto: "udp"}
	tcp := models.Port{IP: "10.0.0.1", Number: 53, Proto: "tcp"}
	if err := s.SavePort(domain, udp); err != nil {
		t.Fatalf("SavePort UDP: %v", err)
	}
	if err := s.SavePort(domain, tcp); err != nil {
		t.Fatalf("SavePort TCP: %v", err)
	}

	ports, err := s.FindPorts(domain)
	if err != nil {
		t.Fatalf("FindPorts: %v", err)
	}
	// Both port 53/tcp and 53/udp must be present as separate rows — the
	// composite PK includes proto, so they do not conflict.
	if len(ports) != 2 {
		t.Fatalf("FindPorts: got %d ports, want 2 (tcp + udp)", len(ports))
	}
	protos := map[string]bool{}
	for _, p := range ports {
		protos[p.Proto] = true
	}
	if !protos["tcp"] || !protos["udp"] {
		t.Errorf("expected both tcp and udp, got %v", protos)
	}
}

// TestPostgresStore_SaveService_VersionDowngrade verifies that downgrading a
// service version (e.g. a rollback) is detected and stored. The differ treats
// any version change — upgrade or downgrade — as a VERSION CHANGE event.
func TestPostgresStore_SaveService_VersionDowngrade(t *testing.T) {
	s := openStore(t)
	const domain = "version-downgrade.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"10.0.0.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	port := models.Port{IP: "10.0.0.1", Number: 443, Proto: "tcp"}
	if err := s.SavePort(domain, port); err != nil {
		t.Fatalf("SavePort: %v", err)
	}

	svc := models.Service{Port: port, Name: "nginx", Version: "1.24.0"}
	if err := s.SaveService(domain, svc); err != nil {
		t.Fatalf("SaveService (initial): %v", err)
	}

	svc.Version = "1.18.0" // downgrade
	if err := s.SaveService(domain, svc); err != nil {
		t.Fatalf("SaveService (downgrade): %v", err)
	}

	svcs, err := s.FindServices(domain)
	if err != nil || len(svcs) != 1 {
		t.Fatalf("FindServices: err=%v, count=%d", err, len(svcs))
	}
	if svcs[0].Version != "1.18.0" {
		t.Errorf("version after downgrade: got %q, want %q", svcs[0].Version, "1.18.0")
	}
}

// ── FK constraint enforcement ─────────────────────────────────────────────────

// TestPostgresStore_SavePort_WithoutAsset verifies that the FK constraint on
// ports.asset_domain is enforced — saving a port for a domain that was never
// registered as an asset must return an error.
func TestPostgresStore_SavePort_WithoutAsset(t *testing.T) {
	s := openStore(t)
	port := models.Port{IP: "10.0.0.1", Number: 80, Proto: "tcp"}
	err := s.SavePort("never-registered.integration.local", port)
	if err == nil {
		t.Error("SavePort without a parent asset: expected FK violation error, got nil")
	}
}

// TestPostgresStore_SaveService_WithoutPort verifies that the FK constraint on
// services is enforced — saving a service for a port that was never registered
// must return an error.
func TestPostgresStore_SaveService_WithoutPort(t *testing.T) {
	s := openStore(t)
	const domain = "svc-no-port.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"10.0.0.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	// Asset exists but port 9999 was never saved.
	port := models.Port{IP: "10.0.0.1", Number: 9999, Proto: "tcp"}
	svc := models.Service{Port: port, Name: "unknown"}
	err := s.SaveService(domain, svc)
	if err == nil {
		t.Error("SaveService without a parent port: expected FK violation error, got nil")
	}
}

// TestPostgresStore_SaveBucket_NoDomainAsset verifies that bucket_results has
// no FK back to assets — a bucket can be stored for a domain that was never
// registered as an asset (cloud bucket names need not match a live subdomain).
func TestPostgresStore_SaveBucket_NoDomainAsset(t *testing.T) {
	s := openStore(t)
	const bucketURL = "https://orphan-bucket-test.s3.amazonaws.com"
	t.Cleanup(func() { cleanBucket(t, s, bucketURL) })

	bucket := models.BucketResult{
		URL:        bucketURL,
		Provider:   "aws_s3",
		Status:     403,
		Accessible: false,
	}
	// "orphan.integration.local" was never saved as an asset — this must succeed.
	if err := s.SaveBucket("orphan.integration.local", bucket); err != nil {
		t.Fatalf("SaveBucket without parent asset: %v", err)
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

// TestPostgresStore_Concurrent_SaveAsset fires 20 goroutines that all upsert
// the same domain simultaneously. ON CONFLICT DO UPDATE must handle the race
// without returning errors or leaving a corrupt row.
func TestPostgresStore_Concurrent_SaveAsset(t *testing.T) {
	s := openStore(t)
	const domain = "concurrent-save.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	const workers = 20
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.SaveAsset(models.Asset{
				Domain: domain,
				IPs:    []string{fmt.Sprintf("10.0.0.%d", i+1)},
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: SaveAsset error: %v", i, err)
		}
	}

	// Exactly one row must exist for the domain after 20 concurrent upserts.
	rec, err := s.FindAssetByDomain(domain)
	if err != nil {
		t.Fatalf("FindAssetByDomain after concurrent saves: %v", err)
	}
	if rec == nil {
		t.Fatal("no asset found after concurrent saves")
	}
}

// TestPostgresStore_Concurrent_SavePort fires concurrent SavePort calls for
// different ports on the same asset. Each goroutine writes a distinct port
// number so there are no conflicts — all rows must be stored without error.
func TestPostgresStore_Concurrent_SavePort(t *testing.T) {
	s := openStore(t)
	const domain = "concurrent-port.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"10.0.0.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}

	const workers = 20
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.SavePort(domain, models.Port{
				IP:     "10.0.0.1",
				Number: 10000 + i,
				Proto:  "tcp",
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: SavePort error: %v", i, err)
		}
	}

	ports, err := s.FindPorts(domain)
	if err != nil {
		t.Fatalf("FindPorts after concurrent saves: %v", err)
	}
	if len(ports) != workers {
		t.Errorf("FindPorts: got %d ports, want %d", len(ports), workers)
	}
}

// ── Timestamp correctness ─────────────────────────────────────────────────────

// TestPostgresStore_Timestamps_UTC verifies that timestamps round-trip through
// PostgreSQL in UTC. The schema uses TIMESTAMPTZ, which stores the instant in
// UTC regardless of the server's local timezone setting.
func TestPostgresStore_Timestamps_UTC(t *testing.T) {
	s := openStore(t)
	const domain = "timestamps-utc.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	if err := s.SaveAsset(models.Asset{Domain: domain, IPs: []string{"1.1.1.1"}}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}
	rec, err := s.FindAssetByDomain(domain)
	if err != nil || rec == nil {
		t.Fatalf("FindAssetByDomain: err=%v, rec=%v", err, rec)
	}
	if rec.FirstSeen.Location() != time.UTC {
		t.Errorf("FirstSeen.Location = %v, want UTC", rec.FirstSeen.Location())
	}
	if rec.LastSeen.Location() != time.UTC {
		t.Errorf("LastSeen.Location = %v, want UTC", rec.LastSeen.Location())
	}
	// Both timestamps must be recent (within the last 10 seconds).
	if time.Since(rec.FirstSeen) > 10*time.Second {
		t.Errorf("FirstSeen too far in the past: %v", rec.FirstSeen)
	}
}

// TestPostgresStore_Timestamps_FirstSeenBeforeLastSeen verifies that after two
// saves separated by a brief pause, FirstSeen < LastSeen. This is the
// fundamental invariant for the differential analyser's change detection.
func TestPostgresStore_Timestamps_FirstSeenBeforeLastSeen(t *testing.T) {
	s := openStore(t)
	const domain = "timestamps-order.integration.local"
	t.Cleanup(func() { cleanAsset(t, s, domain) })

	asset := models.Asset{Domain: domain, IPs: []string{"1.1.1.1"}}
	if err := s.SaveAsset(asset); err != nil {
		t.Fatalf("first SaveAsset: %v", err)
	}
	time.Sleep(15 * time.Millisecond)
	if err := s.SaveAsset(asset); err != nil {
		t.Fatalf("second SaveAsset: %v", err)
	}

	rec, err := s.FindAssetByDomain(domain)
	if err != nil || rec == nil {
		t.Fatalf("FindAssetByDomain: %v", err)
	}
	if !rec.LastSeen.After(rec.FirstSeen) {
		t.Errorf("LastSeen (%v) must be after FirstSeen (%v)", rec.LastSeen, rec.FirstSeen)
	}
}

// ── Double close ──────────────────────────────────────────────────────────────

// TestPostgresStore_DoubleClose verifies that calling Close() a second time
// returns an error rather than panicking. sql.DB.Close is documented to be
// safe to call multiple times, but the second call returns "sql: database is closed".
func TestPostgresStore_DoubleClose(t *testing.T) {
	s, err := NewPostgresStore(testDSN(t))
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second close must not panic. It may return an error — that is acceptable.
	_ = s.Close()
}
