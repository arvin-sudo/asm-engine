package discovery

import "strings"

// inScope reports whether name belongs to the scan target.
//
// A name is in scope if it equals the target apex ("example.com") or is a
// direct subdomain of it ("api.example.com", "*.example.com"). Any other name
// — including unrelated domains that may appear on a shared TLS certificate —
// is out of scope and must be discarded before it reaches the pipeline.
//
// All three discoverers (CT logs, HackerTarget, WayBackMachine) apply the same
// filter, so centralising it here ensures consistent scoping behaviour and
// prevents a future change from diverging silently in one source.
func inScope(name, target string) bool {
	return name == target || strings.HasSuffix(name, "."+target)
}
