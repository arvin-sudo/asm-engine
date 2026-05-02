package discovery

import "net/http"

// HTTPClient is the interface used by any HTTP-based discoverer in this package.
//
// Why define our own interface instead of accepting *http.Client directly?
// The standard library's *http.Client is a concrete type. Any code that
// depends on it can only be tested by making real network requests — which
// makes tests slow, non-deterministic, and dependent on external services
// being reachable.
//
// By depending on this narrow, single-method interface instead, we can inject
// a mock in tests that returns controlled, instant responses. The production
// code path passes &http.Client{}, which already satisfies this interface
// with no adapter needed.
//
// This interface will be reused by the cloud bucket hunter in Phase 3, which
// also uses HTTP HEAD requests to probe storage endpoints.
type HTTPClient interface {
	// Get issues an HTTP GET request to url and returns the server's response.
	// The caller is responsible for closing resp.Body when done with it.
	Get(url string) (*http.Response, error)
}
