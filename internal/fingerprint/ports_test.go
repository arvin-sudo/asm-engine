package fingerprint

import "testing"

// TestBuildPortMap verifies the membership-map helper used by both fingerprinter
// constructors. buildPortMap has no higher-level test that pins its output
// directly — the fingerprinter integration tests exercise the constructors but
// not the resulting map contents.
func TestBuildPortMap(t *testing.T) {
	t.Run("empty slice returns empty map", func(t *testing.T) {
		m := buildPortMap(nil)
		if len(m) != 0 {
			t.Errorf("buildPortMap(nil) = %v, want empty map", m)
		}
	})

	t.Run("single port is present in map", func(t *testing.T) {
		m := buildPortMap([]int{80})
		if !m[80] {
			t.Error("buildPortMap([80]): port 80 not found in result")
		}
		if len(m) != 1 {
			t.Errorf("buildPortMap([80]): len = %d, want 1", len(m))
		}
	})

	t.Run("all ports in slice are present", func(t *testing.T) {
		ports := []int{80, 443, 8080, 8443, 8888}
		m := buildPortMap(ports)
		if len(m) != len(ports) {
			t.Fatalf("buildPortMap(%v): len = %d, want %d", ports, len(m), len(ports))
		}
		for _, p := range ports {
			if !m[p] {
				t.Errorf("port %d not found in map", p)
			}
		}
	})

	t.Run("duplicate entries are idempotent", func(t *testing.T) {
		// The same port listed twice must not inflate the map length.
		m := buildPortMap([]int{80, 80, 443, 443})
		if len(m) != 2 {
			t.Errorf("buildPortMap with duplicates: len = %d, want 2", len(m))
		}
		if !m[80] || !m[443] {
			t.Error("expected ports 80 and 443 to be present")
		}
	})

	t.Run("unlisted port is absent", func(t *testing.T) {
		m := buildPortMap([]int{80, 443})
		if m[8080] {
			t.Error("port 8080 should not be present in map built from [80, 443]")
		}
	})
}
