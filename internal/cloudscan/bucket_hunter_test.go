package cloudscan

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockHeadClient implements HeadClient for testing.
// Responses are keyed by URL; any URL not in the map returns 404.
// URLs in failURLs return a network error instead of a response.
type mockHeadClient struct {
	responses map[string]int  // url → HTTP status code
	failURLs  map[string]bool // url → return error instead of response
}

func (m *mockHeadClient) Head(url string) (*http.Response, error) {
	if m.failURLs != nil && m.failURLs[url] {
		return nil, errors.New("mock network error")
	}
	status := http.StatusNotFound
	if m.responses != nil {
		if s, ok := m.responses[url]; ok {
			status = s
		}
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func TestBucketHunter_Scan(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		responses      map[string]int
		failURLs       map[string]bool
		wantCount      int
		wantAccessible int // number of results where Accessible == true
	}{
		{
			name:   "publicly accessible S3 bucket is reported",
			domain: "example.com",
			responses: map[string]int{
				"https://example.s3.amazonaws.com": http.StatusOK,
			},
			wantCount:      1,
			wantAccessible: 1,
		},
		{
			name:   "private S3 bucket is reported but not accessible",
			domain: "example.com",
			responses: map[string]int{
				"https://example.s3.amazonaws.com": http.StatusForbidden,
			},
			wantCount:      1,
			wantAccessible: 0,
		},
		{
			name:      "all 404 responses produce empty results",
			domain:    "example.com",
			wantCount: 0,
		},
		{
			name:   "network errors are silently skipped",
			domain: "example.com",
			failURLs: map[string]bool{
				"https://example.s3.amazonaws.com": true,
			},
			// Only the one probed URL fails; all others return the default 404.
			// No result should be returned.
			wantCount: 0,
		},
		{
			name:   "multiple buckets across providers are all reported",
			domain: "corp.io",
			responses: map[string]int{
				"https://corp.s3.amazonaws.com":                               http.StatusOK,
				"https://corp.blob.core.windows.net/corp?restype=container":  http.StatusForbidden,
			},
			wantCount:      2,
			wantAccessible: 1,
		},
		{
			name:   "Azure Blob private container is reported",
			domain: "example.com",
			responses: map[string]int{
				"https://example.blob.core.windows.net/example?restype=container": http.StatusForbidden,
			},
			wantCount:      1,
			wantAccessible: 0,
		},
		{
			name:   "path-style S3 URL is also probed",
			domain: "example.com",
			responses: map[string]int{
				"https://s3.amazonaws.com/example": http.StatusOK,
			},
			wantCount:      1,
			wantAccessible: 1,
		},
		{
			name:   "GCP path-style public bucket is reported",
			domain: "example.com",
			responses: map[string]int{
				"https://storage.googleapis.com/example": http.StatusOK,
			},
			wantCount:      1,
			wantAccessible: 1,
		},
		{
			name:   "GCP virtual-hosted private bucket is reported",
			domain: "example.com",
			responses: map[string]int{
				"https://example.storage.googleapis.com": http.StatusForbidden,
			},
			wantCount:      1,
			wantAccessible: 0,
		},
		{
			name:   "multiple buckets across all three providers are reported",
			domain: "corp.io",
			responses: map[string]int{
				"https://corp.s3.amazonaws.com":                              http.StatusOK,
				"https://corp.blob.core.windows.net/corp?restype=container": http.StatusForbidden,
				"https://storage.googleapis.com/corp":                       http.StatusOK,
			},
			wantCount:      3,
			wantAccessible: 2,
		},
		{
			// An empty domain must return immediately without probing any URL.
			// candidatesFromDomain("") generates names like "" and "-backup" that
			// produce malformed URLs; the guard prevents those from ever being built.
			name:      "empty domain produces no results",
			domain:    "",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockHeadClient{responses: tt.responses, failURLs: tt.failURLs}
			hunter := NewBucketHunter(client)

			results, err := hunter.Scan(tt.domain)
			if err != nil {
				t.Fatalf("Scan(%q) returned unexpected error: %v", tt.domain, err)
			}
			if len(results) != tt.wantCount {
				t.Errorf("Scan(%q): got %d result(s), want %d; results: %v",
					tt.domain, len(results), tt.wantCount, results)
			}
			var gotAccessible int
			for _, r := range results {
				if r.Accessible {
					gotAccessible++
				}
			}
			if gotAccessible != tt.wantAccessible {
				t.Errorf("Scan(%q): got %d accessible result(s), want %d",
					tt.domain, gotAccessible, tt.wantAccessible)
			}
		})
	}
}

func TestBucketHunter_Scan_ResultFields(t *testing.T) {
	// Verify that every field of a returned BucketResult is populated correctly.
	const targetURL = "https://example.s3.amazonaws.com"
	client := &mockHeadClient{
		responses: map[string]int{targetURL: http.StatusOK},
	}
	hunter := NewBucketHunter(client)

	results, err := hunter.Scan("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found bool
	for _, r := range results {
		if r.URL != targetURL {
			continue
		}
		found = true
		if r.Provider != "aws_s3" {
			t.Errorf("Provider = %q, want %q", r.Provider, "aws_s3")
		}
		if r.Status != http.StatusOK {
			t.Errorf("Status = %d, want %d", r.Status, http.StatusOK)
		}
		if !r.Accessible {
			t.Error("Accessible = false, want true for status 200")
		}
	}
	if !found {
		t.Fatalf("expected result for URL %q not found in %v", targetURL, results)
	}
}

func TestCandidatesFromDomain(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		wantIn    []string // must appear in the returned slice
		wantCount int      // exact expected length (0 = skip length check)
	}{
		{
			name:   "simple domain uses leftmost label as base",
			domain: "example.com",
			// 10 suffix variants + "example-com" dotSlug = 11
			wantIn:    []string{"example", "example-backup", "example-dev", "example-com"},
			wantCount: 11,
		},
		{
			name:   "subdomain uses leftmost label",
			domain: "api.example.com",
			wantIn: []string{"api", "api-backup", "api-dev", "api-example-com"},
		},
		{
			name: "single-label domain skips duplicate dotSlug",
			// base = "example", dotSlug = "example" → same, not added twice
			domain:    "example",
			wantIn:    []string{"example", "example-backup"},
			wantCount: 10, // only the 10 suffix variants, no extra dotSlug
		},
		{
			name:   "all common suffixes are generated",
			domain: "corp.io",
			wantIn: []string{
				"corp", "corp-backup", "corp-dev", "corp-staging", "corp-prod",
				"corp-data", "corp-logs", "corp-assets", "corp-uploads", "corp-static",
				"corp-io",
			},
		},
		{
			name:   "domain is lowercased",
			domain: "EXAMPLE.COM",
			wantIn: []string{"example", "example-com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := candidatesFromDomain(tt.domain)

			if tt.wantCount != 0 && len(got) != tt.wantCount {
				t.Errorf("candidatesFromDomain(%q): got %d candidate(s), want %d; candidates: %v",
					tt.domain, len(got), tt.wantCount, got)
			}

			gotSet := make(map[string]bool, len(got))
			for _, c := range got {
				gotSet[c] = true
			}
			for _, want := range tt.wantIn {
				if !gotSet[want] {
					t.Errorf("candidatesFromDomain(%q): missing expected candidate %q; got %v",
						tt.domain, want, got)
				}
			}

			// Duplicates are a correctness bug: the same URL would be probed twice.
			seen := make(map[string]bool)
			for _, c := range got {
				if seen[c] {
					t.Errorf("candidatesFromDomain(%q): duplicate candidate %q", tt.domain, c)
				}
				seen[c] = true
			}
		})
	}
}
