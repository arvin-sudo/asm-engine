package discovery

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockHTTPClient is a test double for HTTPClient.
type mockHTTPClient struct {
	body       string
	statusCode int
	err        error
}

func (m *mockHTTPClient) Get(_ string) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(strings.NewReader(m.body)),
	}, nil
}

func TestCTDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name        string
		client      *mockHTTPClient
		wantCount   int
		wantErr     bool
		wantSource  string
	}{
		{
			name: "two unique subdomains",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[{"name_value":"api.example.com"},{"name_value":"www.example.com"}]`,
			},
			wantCount:  2,
			wantErr:    false,
			wantSource: "ct_log",
		},
		{
			name: "duplicate entries are deduplicated",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[{"name_value":"api.example.com"},{"name_value":"api.example.com"}]`,
			},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "empty response returns empty slice",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[]`,
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "non-200 status returns error",
			client: &mockHTTPClient{
				statusCode: 429,
				body:       ``,
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
				body:       `not valid json`,
			},
			wantErr: true,
		},
		{
			name: "multi-SAN entry is split into separate subdomains",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[{"name_value":"*.example.com\nexample.com"}]`,
			},
			wantCount:  2,
			wantErr:    false,
			wantSource: "ct_log",
		},
		{
			name: "multi-SAN with duplicate across entries is deduplicated",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[{"name_value":"api.example.com\nwww.example.com"},{"name_value":"www.example.com"}]`,
			},
			wantCount: 2,
			wantErr:   false,
		},
		{
			name: "mixed-case entries are normalised to lowercase and deduplicated",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[{"name_value":"API.example.com"},{"name_value":"api.example.com"}]`,
			},
			wantCount: 1,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewCTDiscoverer(tt.client)
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
				t.Errorf("got %d subdomains, want %d", len(got), tt.wantCount)
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
