package fingerprint

import "github.com/arvin-sudo/asm-engine/pkg/models"

// Fingerprinter identifies the service and version running on an open port.
type Fingerprinter interface {
	Fingerprint(port models.Port) (models.Service, error)
}
