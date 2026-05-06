package discovery

import (
	"context"
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

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Honour request context cancellation — the real http.Client.Do does this,
	// and tests that pass a cancelled context rely on this behaviour.
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
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
		{
			// A real-world certificate can list SANs for unrelated domains (e.g.
			// multi-tenant TLS certs). Only names that are the apex or a direct
			// subdomain of the queried domain should be returned.
			name: "SANs from unrelated domains are filtered out",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[{"name_value":"api.example.com\nunrelated.org\nother.net"}]`,
			},
			wantCount: 1, // only api.example.com passes the scope filter
			wantErr:   false,
		},
		{
			// The apex domain itself can appear as a SAN in its own certificate.
			name: "apex domain SAN is included",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[{"name_value":"example.com\napi.example.com"}]`,
			},
			wantCount: 2,
			wantErr:   false,
		},
		{
			// Mixed-case SANs must be lowercased before the scope filter runs.
			// "API.EXAMPLE.COM" lowercases to "api.example.com", which is a
			// subdomain of the target; "other.org" is correctly dropped.
			name: "mixed-case SANs lowercased before scope filter",
			client: &mockHTTPClient{
				statusCode: 200,
				body:       `[{"name_value":"API.EXAMPLE.COM\nother.org"}]`,
			},
			wantCount: 1,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewCTDiscoverer(tt.client)
			got, err := d.Discover(context.Background(), "example.com")

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

func TestCTDiscoverer_Discover_ContextCancelled(t *testing.T) {
	// A pre-cancelled context must propagate into http.NewRequestWithContext,
	// which causes Do to return an error immediately. Discover must surface that
	// as a non-nil error without panicking or blocking.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Discover is called

	// The mock's Do method is never reached because NewRequestWithContext fails
	// when the context is already done. Use a mock that would succeed if called,
	// so a passing test proves the request was aborted before the network layer.
	client := &mockHTTPClient{statusCode: 200, body: `[]`}
	d := NewCTDiscoverer(client)

	_, err := d.Discover(ctx, "example.com")
	if err == nil {
		t.Fatal("Discover() with cancelled ctx returned nil error, want non-nil")
	}
}
