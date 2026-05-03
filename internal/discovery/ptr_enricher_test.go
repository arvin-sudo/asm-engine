package discovery

import (
	"errors"
	"testing"
)

// mockPTRResolver is a test double for PTRResolver. Responses are keyed by IP
// address; IPs in failIPs return an error instead of a response.
type mockPTRResolver struct {
	responses map[string][]string // ip → list of PTR hostnames (with trailing dot)
	failIPs   map[string]bool     // ip → return error instead of response
}

func (m *mockPTRResolver) LookupAddr(addr string) ([]string, error) {
	if m.failIPs != nil && m.failIPs[addr] {
		return nil, errors.New("mock PTR lookup failure")
	}
	if names, ok := m.responses[addr]; ok {
		return names, nil
	}
	return nil, nil
}

func TestPTREnricher_Enrich(t *testing.T) {
	tests := []struct {
		name      string
		resolver  *mockPTRResolver
		ips       []string
		wantCount int
		wantNames []string
	}{
		{
			name: "single IP with PTR record returns one subdomain",
			resolver: &mockPTRResolver{
				responses: map[string][]string{
					"1.2.3.4": {"host.example.com."},
				},
			},
			ips:       []string{"1.2.3.4"},
			wantCount: 1,
			wantNames: []string{"host.example.com"},
		},
		{
			// net.LookupAddr returns FQDNs with a trailing dot. The enricher
			// must strip it before returning so callers can use the name
			// directly as a DNS query target.
			name: "trailing dot is stripped from FQDN",
			resolver: &mockPTRResolver{
				responses: map[string][]string{
					"1.2.3.4": {"host.example.com."},
				},
			},
			ips:       []string{"1.2.3.4"},
			wantCount: 1,
			wantNames: []string{"host.example.com"},
		},
		{
			// An IP that appears twice in the input should only be looked up
			// once — querying the same IP twice is redundant and wastes DNS
			// round trips.
			name: "duplicate IPs are queried only once",
			resolver: &mockPTRResolver{
				responses: map[string][]string{
					"1.2.3.4": {"host.example.com."},
				},
			},
			ips:       []string{"1.2.3.4", "1.2.3.4"},
			wantCount: 1,
		},
		{
			name: "multiple distinct IPs with separate PTR records",
			resolver: &mockPTRResolver{
				responses: map[string][]string{
					"1.2.3.4": {"api.example.com."},
					"5.6.7.8": {"db.internal.example.com."},
				},
			},
			ips:       []string{"1.2.3.4", "5.6.7.8"},
			wantCount: 2,
			wantNames: []string{"api.example.com", "db.internal.example.com"},
		},
		{
			// Two different IPs pointing to the same hostname via PTR should
			// produce only one subdomain (deduplication by hostname).
			name: "same hostname returned by different IPs is deduplicated",
			resolver: &mockPTRResolver{
				responses: map[string][]string{
					"1.2.3.4": {"shared.example.com."},
					"5.6.7.8": {"shared.example.com."},
				},
			},
			ips:       []string{"1.2.3.4", "5.6.7.8"},
			wantCount: 1,
			wantNames: []string{"shared.example.com"},
		},
		{
			name: "PTR lookup failure is silently skipped",
			resolver: &mockPTRResolver{
				failIPs: map[string]bool{"1.2.3.4": true},
			},
			ips:       []string{"1.2.3.4"},
			wantCount: 0,
		},
		{
			name:      "IP with no PTR record returns empty slice",
			resolver:  &mockPTRResolver{},
			ips:       []string{"1.2.3.4"},
			wantCount: 0,
		},
		{
			name:      "empty IP list returns empty slice",
			resolver:  &mockPTRResolver{},
			ips:       nil,
			wantCount: 0,
		},
		{
			name: "all results are tagged with ptr source",
			resolver: &mockPTRResolver{
				responses: map[string][]string{
					"1.2.3.4": {"host.example.com."},
				},
			},
			ips:       []string{"1.2.3.4"},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewPTREnricher(tt.resolver)
			got := e.Enrich(tt.ips)

			if len(got) != tt.wantCount {
				t.Errorf("Enrich: got %d result(s), want %d; results: %v", len(got), tt.wantCount, got)
			}

			gotSet := make(map[string]bool, len(got))
			for _, s := range got {
				gotSet[s.Name] = true
			}
			for _, want := range tt.wantNames {
				if !gotSet[want] {
					t.Errorf("Enrich: missing expected hostname %q; got %v", want, got)
				}
			}

			for _, s := range got {
				if s.Source != ptrSource {
					t.Errorf("Enrich: subdomain %q has Source = %q, want %q", s.Name, s.Source, ptrSource)
				}
			}
		})
	}
}
