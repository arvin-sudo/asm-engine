package discovery

import "github.com/arvin-sudo/asm-engine/pkg/models"

// Discoverer finds subdomains and hosts for a given target domain.
// Implementations can use DNS brute-force, certificate transparency, etc.
type Discoverer interface {
	Discover(domain string) ([]models.Asset, error)
}
