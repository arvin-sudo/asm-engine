package storage

import "github.com/arvin-sudo/asm-engine/pkg/models"

// Store persists and retrieves discovered assets.
// Implementations can use PostgreSQL, SQLite, in-memory, etc.
type Store interface {
	Save(asset models.Asset) error
	FindAll() ([]models.Asset, error)
}
