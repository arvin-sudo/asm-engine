package discovery

import "github.com/arvin-sudo/asm-engine/pkg/models"

// deduplicateSubdomains returns a copy of items with duplicate Names removed,
// preserving the first occurrence of each name in input order.
//
// Why a shared helper rather than inline seen-maps?
// HackerTarget, WayBack, and the DNS intelligence scanner all apply the same
// filter: build a set from Name fields, keep first-seen entries, discard
// repeats. Implementing this identically in four places means four sites where
// the logic could silently diverge. A single function is easier to test and
// harder to misuse.
//
// Time: O(n). Space: O(n) for the seen map. The input slice is not mutated.
func deduplicateSubdomains(items []models.Subdomain) []models.Subdomain {
	seen := make(map[string]struct{}, len(items))
	result := make([]models.Subdomain, 0, len(items))
	for _, s := range items {
		if _, ok := seen[s.Name]; ok {
			continue
		}
		seen[s.Name] = struct{}{}
		result = append(result, s)
	}
	return result
}
