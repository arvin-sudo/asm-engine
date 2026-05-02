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
