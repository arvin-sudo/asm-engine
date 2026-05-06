// Package cloudscan implements Phase 3 of the ASM engine: cloud storage bucket
// discovery. It derives well-known URL patterns from the target domain and probes
// each one with an HTTP HEAD request to determine whether a bucket exists and
// whether it is publicly accessible.
//
// Why is this a separate package from internal/discovery? Discovery concerns
// subdomains and DNS records — passive recon that produces Subdomain and Asset
// values. Cloud scanning concerns cloud storage endpoints — a different attack
// surface that produces BucketResult values. Keeping them separate means neither
// package grows unrelated responsibilities, and Phase 4 (PostgreSQL persistence)
// can store both kinds of findings without either package knowing about the other.
//
// Why does this package define its own HeadClient interface instead of reusing
// discovery.HTTPClient? Both interfaces expose Do, but the contracts differ:
// discovery.HTTPClient is used exclusively for GET requests by OSINT sources,
// while HeadClient is used exclusively for HEAD requests to probe bucket URLs.
// Sharing a single interface would conflate two different semantic roles.
// Keeping them separate means each package states its intent clearly and test
// mocks only need to verify the call pattern they actually exercise.
package cloudscan

import (
	"context"
	"net/http"

	"github.com/arvin-sudo/asm-engine/pkg/models"
)

// HeadClient is the HTTP transport interface used by BucketHunter.
//
// Do is used rather than Head so that callers can construct requests with
// http.NewRequestWithContext and propagate cancellation signals through the
// pipeline. *http.Client satisfies HeadClient directly — its Do method
// signature matches with no adapter needed.
type HeadClient interface {
	// Do sends an HTTP request and returns the server's response.
	// The caller is responsible for closing resp.Body when done with it.
	Do(req *http.Request) (*http.Response, error)
}

// CloudScanner discovers publicly accessible or misconfigured cloud storage
// buckets associated with a target domain.
//
// Implementations probe well-known URL patterns and return a BucketResult for
// each endpoint that exists (status 200 or 403). Endpoints that return 404 are
// discarded — a 404 from a cloud provider means the bucket name is simply not
// registered, which is the expected outcome for most candidates.
//
// ctx is forwarded to every outbound HTTP request so the pipeline's
// cancellation signal can interrupt in-flight probes immediately.
type CloudScanner interface {
	Scan(ctx context.Context, domain string) ([]models.BucketResult, error)
}
