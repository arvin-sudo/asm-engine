package cloudscan

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

const (
	// providerAWSS3 identifies findings that come from an Amazon S3 endpoint.
	providerAWSS3 = "aws_s3"

	// providerAzureBlob identifies findings that come from an Azure Blob Storage endpoint.
	providerAzureBlob = "azure_blob"

	// providerGCPStorage identifies findings that come from a Google Cloud Storage endpoint.
	providerGCPStorage = "gcp_storage"
)

// BucketHunter implements CloudScanner by sending HTTP HEAD requests to
// well-known cloud storage URL patterns derived from the target domain.
//
// For each candidate name derived from the domain, BucketHunter probes AWS S3
// and Azure Blob Storage endpoints. Status 200 means the bucket is publicly
// accessible — a direct security finding. Status 403 means the bucket exists
// but requires authentication — confirming it as a real asset even if not
// immediately exploitable. Status 404 is discarded as not found.
//
// Probes run sequentially. Cloud storage endpoints (s3.amazonaws.com,
// blob.core.windows.net) are always available and respond in milliseconds.
// The candidate set is bounded to a fixed list, so total probe time is well
// within acceptable CLI latency. Concurrency would complicate the implementation
// for no measurable gain at this scale — it can be introduced later if profiling
// shows it is needed.
type BucketHunter struct {
	client HeadClient
}

// NewBucketHunter constructs a BucketHunter using the given HTTP client.
// The caller is responsible for configuring the client's timeout. A value of
// 5–10 seconds is recommended: cloud storage DNS always resolves, so most
// probes return quickly, but a generous deadline avoids false misses on
// high-latency connections.
func NewBucketHunter(client HeadClient) *BucketHunter {
	return &BucketHunter{client: client}
}

// Scan derives bucket name candidates from domain and probes each one on AWS S3
// and Azure Blob Storage. It returns a BucketResult for every endpoint that
// responds with 200 (publicly accessible) or 403 (exists but private).
// 404 responses and network-level errors are silently skipped — one unreachable
// candidate must not stop the rest of the sweep.
//
// An empty domain returns immediately with no results. candidatesFromDomain("")
// would otherwise generate candidates like "" and "-backup" that produce
// malformed probe URLs rejected at the DNS or HTTP layer.
func (h *BucketHunter) Scan(domain string) ([]models.BucketResult, error) {
	if domain == "" {
		return nil, nil
	}
	candidates := candidatesFromDomain(domain)
	urls := buildURLs(candidates)

	var results []models.BucketResult
	for _, entry := range urls {
		resp, err := h.client.Head(entry.url)
		if err != nil {
			// Network-level failure: DNS error, connection refused, timeout.
			// Skip — it does not prove the bucket is absent, only that this
			// particular probe could not reach the endpoint right now.
			continue
		}
		resp.Body.Close()

		// Report only confirmed-present buckets.
		// 200 = publicly accessible (high-severity finding).
		// 403 = exists but private (informational — confirms the asset is real).
		// All other status codes, including 404, are treated as not found.
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
			continue
		}

		results = append(results, models.BucketResult{
			URL:        entry.url,
			Provider:   entry.provider,
			Status:     resp.StatusCode,
			Accessible: resp.StatusCode == http.StatusOK,
		})
	}

	return results, nil
}

// urlEntry pairs a probed URL with the provider identifier for that endpoint.
type urlEntry struct {
	url      string
	provider string
}

// buildURLs constructs probe URLs for each candidate bucket name.
//
// Two AWS S3 patterns are generated per candidate:
//   - Virtual-hosted style (https://<name>.s3.amazonaws.com) is the primary
//     pattern; all modern S3 buckets respond here.
//   - Path style (https://s3.amazonaws.com/<name>) is the legacy pattern;
//     still used by some tools and older buckets that pre-date virtual hosting.
//
// One Azure Blob Storage pattern per candidate:
//   - https://<name>.blob.core.windows.net/<name>?restype=container probes
//     the container of the same name within the storage account. This returns
//     200 for public containers and 403 for private ones — the same semantics
//     as S3. The storage account root alone returns 400 for existing accounts
//     (no resource type specified), which would require special-casing; the
//     container URL gives clean 200/403 semantics without that complexity.
//
// Two GCP Cloud Storage patterns per candidate:
//   - Path style (https://storage.googleapis.com/<name>) is the standard
//     XML API pattern; public buckets return 200, private return 403.
//   - Virtual-hosted style (https://<name>.storage.googleapis.com) mirrors
//     S3 virtual hosting and is used by some CDN and SDK configurations.
func buildURLs(candidates []string) []urlEntry {
	var entries []urlEntry
	for _, name := range candidates {
		entries = append(entries,
			urlEntry{
				url:      fmt.Sprintf("https://%s.s3.amazonaws.com", name),
				provider: providerAWSS3,
			},
			urlEntry{
				url:      fmt.Sprintf("https://s3.amazonaws.com/%s", name),
				provider: providerAWSS3,
			},
			urlEntry{
				// Container is named after the account — the most common
				// pattern in misconfigured deployments.
				url:      fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container", name, name),
				provider: providerAzureBlob,
			},
			urlEntry{
				url:      fmt.Sprintf("https://storage.googleapis.com/%s", name),
				provider: providerGCPStorage,
			},
			urlEntry{
				url:      fmt.Sprintf("https://%s.storage.googleapis.com", name),
				provider: providerGCPStorage,
			},
		)
	}
	return entries
}

// candidatesFromDomain derives bucket name candidates from the target domain.
//
// Cloud storage bucket names are restricted to lowercase alphanumerics and
// hyphens, so the domain's leftmost label is used as the base
// (e.g. "example" from "example.com"). Common environment and purpose suffixes
// are appended to cover the naming conventions most frequently seen in
// real-world misconfigurations. The full domain with dots replaced by hyphens
// ("example-com") is also included because some teams name buckets after the
// full domain slug.
//
// Deduplication ensures the same candidate name is never probed twice — for
// single-label domains (e.g. "example") the base and dotSlug are identical,
// so the dotSlug is dropped rather than generating a duplicate probe set.
func candidatesFromDomain(domain string) []string {
	// Take the leftmost label as the base candidate name. For "example.com"
	// this gives "example"; for "api.example.com" it gives "api".
	base := domain
	if idx := strings.Index(domain, "."); idx != -1 {
		base = domain[:idx]
	}
	base = strings.ToLower(base)

	// These suffixes reflect the naming conventions most commonly associated
	// with misconfigured or forgotten buckets in real-world cloud environments.
	suffixes := []string{
		"", "-backup", "-dev", "-staging", "-prod",
		"-data", "-logs", "-assets", "-uploads", "-static",
	}

	seen := make(map[string]struct{})
	var candidates []string
	for _, s := range suffixes {
		name := base + s
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			candidates = append(candidates, name)
		}
	}

	// Also probe the full domain slug (dots → hyphens) as a distinct candidate.
	// "example.com" → "example-com"; distinct from the base "example".
	dotSlug := strings.ToLower(strings.ReplaceAll(domain, ".", "-"))
	if _, ok := seen[dotSlug]; !ok {
		candidates = append(candidates, dotSlug)
	}

	return candidates
}
