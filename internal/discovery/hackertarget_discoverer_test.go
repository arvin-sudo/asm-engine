package discovery

import (
	"errors"
	"net/http"
	"testing"
)

func TestHackerTargetDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name       string
		client     *mockHTTPClient
		wantCount  int
		wantErr    bool
		wantSource string
	}{
		{
			name: "two unique subdomains",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       "api.example.com,1.2.3.4\nwww.example.com,5.6.7.8\n",
			},
			wantCount:  2,
			wantSource: "hackertarget",
		},
		{
			name: "duplicate entries are deduplicated",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       "api.example.com,1.2.3.4\napi.example.com,1.2.3.4\n",
			},
			wantCount: 1,
		},
		{
			name: "entries from unrelated domains are filtered out",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       "api.example.com,1.2.3.4\nunrelated.org,9.9.9.9\n",
			},
			wantCount: 1,
		},
		{
			name: "empty response returns empty slice",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       "",
			},
			wantCount: 0,
		},
		{
			// HackerTarget embeds an error string in the body (with a 200 status)
			// when the free-tier quota is exceeded. Lines without a comma are not
			// valid hostname entries and must be skipped.
			name: "error message lines without comma are skipped",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       "API count exceeded - Upgrade for Unlimited API\napi.example.com,1.2.3.4\n",
			},
			wantCount: 1,
		},
		{
			// HTTP 429 means the daily quota is exhausted. The pipeline must
			// continue with results from other sources rather than aborting.
			name: "429 rate limit returns empty slice without error",
			client: &mockHTTPClient{
				statusCode: http.StatusTooManyRequests,
				body:       "",
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "non-200 non-429 status returns error",
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
			name: "mixed-case hostnames are normalised to lowercase",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       "API.example.com,1.2.3.4\n",
			},
			wantCount: 1,
		},
		{
			// The apex domain itself can appear in the HackerTarget response.
			name: "apex domain entry is included",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       "example.com,1.2.3.4\napi.example.com,5.6.7.8\n",
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewHackerTargetDiscoverer(tt.client)
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
