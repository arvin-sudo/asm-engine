package discovery

import (
	"errors"
	"testing"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// stubDiscoverer is a test double for SubdomainDiscoverer. It is local to this
// file because MultiSourceDiscoverer is the only component that composes
// multiple SubdomainDiscoverer implementations and therefore the only one that
// needs a configurable stub at this level.
type stubDiscoverer struct {
	subdomains []models.Subdomain
	err        error
}

func (s *stubDiscoverer) Discover(_ string) ([]models.Subdomain, error) {
	return s.subdomains, s.err
}

// makeSubs builds a Subdomain slice from a list of name/source pairs.
// Keeping construction in one place makes table rows concise.
func makeSubs(pairs ...string) []models.Subdomain {
	if len(pairs)%2 != 0 {
		panic("makeSubs: pairs must be name/source alternating")
	}
	result := make([]models.Subdomain, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		result = append(result, models.Subdomain{Name: pairs[i], Source: pairs[i+1]})
	}
	return result
}

func TestMultiSourceDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name            string
		sources         []SubdomainDiscoverer
		wantCount       int
		wantNames       []string
		wantFirstSource map[string]string // hostname → expected Source tag
		wantErr         bool
	}{
		{
			name: "results from multiple sources are merged",
			sources: []SubdomainDiscoverer{
				&stubDiscoverer{subdomains: makeSubs("api.example.com", "ct_log", "www.example.com", "ct_log")},
				&stubDiscoverer{subdomains: makeSubs("mail.example.com", "hackertarget")},
			},
			wantCount: 3,
			wantNames: []string{"api.example.com", "www.example.com", "mail.example.com"},
		},
		{
			// "api.example.com" appears in both sources; the first source (ct_log)
			// should win — MultiSourceDiscoverer preserves per-source attribution.
			name: "duplicates across sources are deduplicated and first source wins",
			sources: []SubdomainDiscoverer{
				&stubDiscoverer{subdomains: makeSubs("api.example.com", "ct_log")},
				&stubDiscoverer{subdomains: makeSubs("api.example.com", "hackertarget", "www.example.com", "hackertarget")},
			},
			wantCount: 2,
			wantNames: []string{"api.example.com", "www.example.com"},
			wantFirstSource: map[string]string{
				"api.example.com": "ct_log", // first source wins
				"www.example.com": "hackertarget",
			},
		},
		{
			// A single failing source must not abort the pipeline; the other
			// source still contributes its results.
			name: "a failing source is skipped and others still contribute",
			sources: []SubdomainDiscoverer{
				&stubDiscoverer{err: errors.New("source unavailable")},
				&stubDiscoverer{subdomains: makeSubs("api.example.com", "wayback")},
			},
			wantCount: 1,
			wantNames: []string{"api.example.com"},
		},
		{
			// When every source fails the caller must receive an error rather
			// than a silent empty result — total failure is observable.
			name: "all sources failing returns error",
			sources: []SubdomainDiscoverer{
				&stubDiscoverer{err: errors.New("source 1 failed")},
				&stubDiscoverer{err: errors.New("source 2 failed")},
			},
			wantErr: true,
		},
		{
			name:      "no sources registered returns empty slice without error",
			sources:   nil,
			wantCount: 0,
		},
		{
			name: "single source with empty result returns empty slice",
			sources: []SubdomainDiscoverer{
				&stubDiscoverer{subdomains: nil},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMultiSourceDiscoverer(tt.sources...)
			got, err := m.Discover("example.com")

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantCount {
				t.Errorf("got %d subdomain(s), want %d; results: %v", len(got), tt.wantCount, got)
			}

			gotMap := make(map[string]models.Subdomain, len(got))
			for _, s := range got {
				gotMap[s.Name] = s
			}

			for _, want := range tt.wantNames {
				if _, ok := gotMap[want]; !ok {
					t.Errorf("missing expected subdomain %q; got %v", want, got)
				}
			}

			for hostname, wantSrc := range tt.wantFirstSource {
				s, ok := gotMap[hostname]
				if !ok {
					t.Errorf("subdomain %q not found in results", hostname)
					continue
				}
				if s.Source != wantSrc {
					t.Errorf("subdomain %q: Source = %q, want %q", hostname, s.Source, wantSrc)
				}
			}
		})
	}
}
