package scanner

import "github.com/arvin-sudo/asm-engine/pkg/models"

// Scanner probes a host for open ports and returns the results.
// Implementations can use TCP connect, SYN scan, etc.
type Scanner interface {
	Scan(asset models.Asset) ([]models.Port, error)
}
