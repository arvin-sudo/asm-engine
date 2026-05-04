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

// TestBuildURLs verifies the exact URLs and provider labels that buildURLs
// generates for each cloud storage platform. The Scan integration tests exercise
// buildURLs indirectly — they key the mock by URL, so a URL format bug would
// silently pass (the mock would just return 404 and the test would see zero
// results). This test pins the expected URLs directly.
func TestBuildURLs(t *testing.T) {
	t.Run("empty candidates returns no entries", func(t *testing.T) {
		if got := buildURLs(nil); len(got) != 0 {
			t.Errorf("buildURLs(nil) = %d entries, want 0", len(got))
		}
	})

	t.Run("single candidate produces five entries", func(t *testing.T) {
		got := buildURLs([]string{"example"})
		if len(got) != 5 {
			t.Fatalf("buildURLs([example]) = %d entries, want 5; entries: %v", len(got), got)
		}
	})

	t.Run("provider counts are correct for one candidate", func(t *testing.T) {
		got := buildURLs([]string{"example"})
		counts := map[string]int{}
		for _, e := range got {
			counts[e.provider]++
		}
		if counts[providerAWSS3] != 2 {
			t.Errorf("aws_s3 count = %d, want 2", counts[providerAWSS3])
		}
		if counts[providerAzureBlob] != 1 {
			t.Errorf("azure_blob count = %d, want 1", counts[providerAzureBlob])
		}
		if counts[providerGCPStorage] != 2 {
			t.Errorf("gcp_storage count = %d, want 2", counts[providerGCPStorage])
		}
	})

	t.Run("URL formats are correct for candidate example", func(t *testing.T) {
		got := buildURLs([]string{"example"})
		urlSet := make(map[string]string, len(got)) // url → provider
		for _, e := range got {
			urlSet[e.url] = e.provider
		}

		wantURLs := []struct {
			url      string
			provider string
		}{
			{"https://example.s3.amazonaws.com", providerAWSS3},
			{"https://s3.amazonaws.com/example", providerAWSS3},
			{"https://example.blob.core.windows.net/example?restype=container", providerAzureBlob},
			{"https://storage.googleapis.com/example", providerGCPStorage},
			{"https://example.storage.googleapis.com", providerGCPStorage},
		}
		for _, w := range wantURLs {
			got, ok := urlSet[w.url]
			if !ok {
				t.Errorf("missing expected URL %q", w.url)
				continue
			}
			if got != w.provider {
				t.Errorf("URL %q: provider = %q, want %q", w.url, got, w.provider)
			}
		}
	})

	t.Run("two candidates produce ten entries with no cross-contamination", func(t *testing.T) {
		got := buildURLs([]string{"alpha", "beta"})
		if len(got) != 10 {
			t.Fatalf("buildURLs([alpha, beta]) = %d entries, want 10", len(got))
		}
		// Both names must appear in AWS virtual-hosted URLs.
		hasAlpha, hasBeta := false, false
		for _, e := range got {
			if e.url == "https://alpha.s3.amazonaws.com" {
				hasAlpha = true
			}
			if e.url == "https://beta.s3.amazonaws.com" {
				hasBeta = true
			}
		}
		if !hasAlpha {
			t.Error("missing AWS virtual-hosted URL for candidate alpha")
		}
		if !hasBeta {
			t.Error("missing AWS virtual-hosted URL for candidate beta")
		}
	})
}
