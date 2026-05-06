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
// Why Do instead of Get?
// The Do method accepts a fully-constructed *http.Request, which callers build
// with http.NewRequestWithContext. This means the caller's context.Context is
// embedded in the request and propagated into the underlying transport — so a
// cancelled pipeline context cancels the in-flight HTTP connection immediately,
// without waiting for the server to respond. *http.Client already implements
// Do, so the production path requires no adapter. This is the same design used
// by HeadClient in the cloudscan package for identical reasons; keeping both
// interfaces consistent also makes mocks easier to reason about.
//
// Why not share this interface with the cloud bucket hunter in Phase 3?
// Phase 3 only ever needs HEAD requests, not GET. Exposing Do here for phase 3
// to reuse would create a dependency on a method it never calls — a violation
// of Interface Segregation. Phase 3 therefore defines its own narrow HeadClient
// interface independently.
type HTTPClient interface {
	// Do executes the provided HTTP request and returns the server's response.
	// The caller is responsible for closing resp.Body when done with it.
	// Build the request with http.NewRequestWithContext so the caller's
	// context propagates into in-flight connections and can be cancelled.
	Do(req *http.Request) (*http.Response, error)
}
