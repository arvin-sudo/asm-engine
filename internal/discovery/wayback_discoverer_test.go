package discovery

import (
	"errors"
	"testing"
)

// TestParseWayBackRecords directly exercises the CDX record parser. The
// Discover-level tests cover the main cases but leave two branches untested:
// (a) an inner slice that is empty (len == 0), and (b) a URL string that
// url.Parse accepts but produces an empty Host field. Both are guarded by
// explicit continue conditions that are only reachable via direct calls.
func TestParseWayBackRecords(t *testing.T) {
	const target = "example.com"
	const src = "wayback"

	tests := []struct {
		name      string
		records   [][]string
		wantCount int
		wantNames []string
	}{
		{
			name:      "nil records returns empty slice",
			records:   nil,
			wantCount: 0,
		},
		{
			name:      "header-only response returns empty slice",
			records:   [][]string{{"original"}},
			wantCount: 0,
		},
		{
			// The CDX header row is recognised by i==0 AND record[0]=="original".
			// A data row at i==0 with any other value must be processed normally.
			name: "first row that is not the header is treated as data",
			records: [][]string{
				{"https://api.example.com/"},
			},
			wantCount: 1,
			wantNames: []string{"api.example.com"},
		},
		{
			// An inner slice with zero elements satisfies len(record)==0 and must
			// be skipped without panicking.
			name: "empty inner slice is skipped without panic",
			records: [][]string{
				{"original"},
				{},
				{"https://api.example.com/"},
			},
			wantCount: 1,
			wantNames: []string{"api.example.com"},
		},
		{
			// url.Parse("/some/path") produces u.Host=="", so the record is skipped.
			// This exercises the err != nil || u.Host == "" guard that prevents
			// host-less URLs from reaching the scope filter.
			name: "relative path URL has empty Host and is skipped",
			records: [][]string{
				{"original"},
				{"/some/path"},
				{"https://api.example.com/"},
			},
			wantCount: 1,
			wantNames: []string{"api.example.com"},
		},
		{
			// A URL from an unrelated domain must be filtered by the scope check.
			name: "out-of-scope URL is filtered",
			records: [][]string{
				{"original"},
				{"https://unrelated.org/page"},
				{"https://www.example.com/"},
			},
			wantCount: 1,
			wantNames: []string{"www.example.com"},
		},
		{
			// Two records pointing to the same hostname are deduplicated.
			name: "duplicate hostnames are deduplicated",
			records: [][]string{
				{"original"},
				{"https://api.example.com/v1"},
				{"https://api.example.com/v2"},
			},
			wantCount: 1,
			wantNames: []string{"api.example.com"},
		},
		{
			// The source tag must be set on every returned Subdomain.
			name: "returned subdomains carry the correct source tag",
			records: [][]string{
				{"original"},
				{"https://api.example.com/"},
			},
			wantCount: 1,
			wantNames: []string{"api.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseWayBackRecords(tt.records, target, src)

			if len(got) != tt.wantCount {
				t.Fatalf("parseWayBackRecords: got %d result(s), want %d; results: %v",
					len(got), tt.wantCount, got)
			}

			gotSet := make(map[string]string, len(got)) // name → source
			for _, s := range got {
				gotSet[s.Name] = s.Source
			}

			for _, want := range tt.wantNames {
				gotSrc, ok := gotSet[want]
				if !ok {
					t.Errorf("parseWayBackRecords: expected hostname %q not found; got %v", want, got)
					continue
				}
				if gotSrc != src {
					t.Errorf("hostname %q: Source = %q, want %q", want, gotSrc, src)
				}
			}
		})
	}
}

func TestWayBackDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name       string
		client     *mockHTTPClient
		wantCount  int
		wantErr    bool
		wantSource string
	}{
		{
			name: "two unique subdomains from archived URLs",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[["original"],["https://api.example.com/v1"],["https://www.example.com/"]]`,
			},
			wantCount:  2,
			wantSource: "wayback",
		},
		{
			// Two records pointing to the same hostname (different paths) should
			// produce only one Subdomain — deduplication is by hostname, not URL.
			name: "same hostname at different paths is deduplicated",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[["original"],["https://api.example.com/"],["https://api.example.com/v2"]]`,
			},
			wantCount: 1,
		},
		{
			name: "URLs from unrelated domains are filtered out",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[["original"],["https://api.example.com/"],["https://unrelated.org/"]]`,
			},
			wantCount: 1,
		},
		{
			// A response with only the header row means no URLs were archived.
			name: "header-only response returns empty slice",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[["original"]]`,
			},
			wantCount: 0,
		},
		{
			name: "empty JSON array returns empty slice",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[]`,
			},
			wantCount: 0,
		},
		{
			// net/url.Hostname() strips the port, so "api.example.com:8443"
			// and "api.example.com" map to the same hostname.
			name: "URL with port number has port stripped before deduplication",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[["original"],["https://api.example.com:8443/path"],["https://api.example.com/"]]`,
			},
			wantCount: 1,
		},
		{
			name: "non-200 status returns error",
			client: &mockHTTPClient{
				statusCode: 503,
				body:       "",
			},
			wantErr: true,
		},
		{
			name: "network failure returns error",
			client: &mockHTTPClient{
				err: errors.New("connection timeout"),
			},
			wantErr: true,
		},
		{
			name: "malformed JSON returns error",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `not json`,
			},
			wantErr: true,
		},
		{
			name: "mixed-case hostnames are normalised to lowercase",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[["original"],["https://API.EXAMPLE.COM/"]]`,
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewWayBackDiscoverer(tt.client)
			got, err := d.Discover("example.com")

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
				t.Errorf("got %d subdomains, want %d; results: %v", len(got), tt.wantCount, got)
			}
			if tt.wantSource != "" {
				for _, s := range got {
					if s.Source != tt.wantSource {
						t.Errorf("subdomain %q: Source = %q, want %q", s.Name, s.Source, tt.wantSource)
					}
				}
			}
		})
	}
}
