package discovery

import (
	"errors"
	"testing"
)

// mockResolver is a test double for Resolver. It is defined here and not in a
// shared test helper because it is only needed in this file — keeping it local
// avoids polluting the package's exported surface with test infrastructure.
type mockResolver struct {
	addrs []string
	err   error
}

func (m *mockResolver) LookupHost(_ string) ([]string, error) {
	return m.addrs, m.err
}

func TestDNSResolver_Discover(t *testing.T) {
	tests := []struct {
		name     string
		resolver *mockResolver
		domain   string
		wantIPs  []string
		wantErr  bool
	}{
		{
			name:     "single IP returned",
			resolver: &mockResolver{addrs: []string{"93.184.216.34"}},
			domain:   "example.com",
			wantIPs:  []string{"93.184.216.34"},
		},
		{
			name:     "multiple IPs returned for load-balanced host",
			resolver: &mockResolver{addrs: []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"}},
			domain:   "multi.example.com",
			wantIPs:  []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"},
		},
		{
			name:     "domain is preserved verbatim in returned asset",
			resolver: &mockResolver{addrs: []string{"10.0.0.1"}},
			domain:   "api.example.com",
			wantIPs:  []string{"10.0.0.1"},
		},
		{
			name:     "duplicate IPs from resolver are deduplicated",
			resolver: &mockResolver{addrs: []string{"1.2.3.4", "5.6.7.8", "1.2.3.4"}},
			domain:   "multi.example.com",
			wantIPs:  []string{"1.2.3.4", "5.6.7.8"},
		},
		{
			name:     "NXDOMAIN returns error",
			resolver: &mockResolver{err: errors.New("no such host")},
			domain:   "dead.example.com",
			wantErr:  true,
		},
		{
			name:     "resolver network failure returns error",
			resolver: &mockResolver{err: errors.New("connection refused")},
			domain:   "example.com",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDNSResolver(tt.resolver)
			got, err := d.Discover(tt.domain)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Domain != tt.domain {
				t.Errorf("Domain = %q, want %q", got.Domain, tt.domain)
			}
			if len(got.IPs) != len(tt.wantIPs) {
				t.Fatalf("got %d IPs, want %d", len(got.IPs), len(tt.wantIPs))
			}
			for i, ip := range got.IPs {
				if ip != tt.wantIPs[i] {
					t.Errorf("IPs[%d] = %q, want %q", i, ip, tt.wantIPs[i])
				}
			}
		})
	}
}

// TestDeduplicateIPs directly exercises the IP deduplication helper. Discover
// tests cover it indirectly but do not pin the order-preservation guarantee or
// the all-duplicates edge case.
func TestDeduplicateIPs(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
		want []string
	}{
		{
			name: "nil input returns empty slice",
			ips:  nil,
			want: []string{},
		},
		{
			name: "empty slice returns empty slice",
			ips:  []string{},
			want: []string{},
		},
		{
			// Order must be preserved so the output is deterministic.
			name: "no duplicates preserves order",
			ips:  []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"},
			want: []string{"1.2.3.4", "5.6.7.8", "9.10.11.12"},
		},
		{
			// The first occurrence is kept; subsequent occurrences are dropped.
			name: "one duplicate in middle is removed, first kept",
			ips:  []string{"1.2.3.4", "5.6.7.8", "1.2.3.4"},
			want: []string{"1.2.3.4", "5.6.7.8"},
		},
		{
			// All entries the same: only the first is kept.
			name: "all same IPs reduces to single entry",
			ips:  []string{"1.2.3.4", "1.2.3.4", "1.2.3.4"},
			want: []string{"1.2.3.4"},
		},
		{
			// Multiple distinct duplicates, order of first occurrence preserved.
			name: "multiple distinct duplicates preserved in order of first occurrence",
			ips:  []string{"a", "b", "a", "c", "b"},
			want: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicateIPs(tt.ips)
			if len(got) != len(tt.want) {
				t.Fatalf("deduplicateIPs(%v) = %v, want %v", tt.ips, got, tt.want)
			}
			for i, ip := range got {
				if ip != tt.want[i] {
					t.Errorf("deduplicateIPs result[%d] = %q, want %q", i, ip, tt.want[i])
				}
			}
		})
	}
}
