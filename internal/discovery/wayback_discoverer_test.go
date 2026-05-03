package discovery

import (
	"errors"
	"testing"
)

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
