package store

import (
	"context"

	auth "github.com/hivemindd/auth-service/internal/auth"
	"gorm.io/gorm"
)

// PostgresStore embeds gorm type to provide extra methods specific to auth-service.
type PostgresStore struct {
	db *gorm.DB
}

func NewPostgresStore(db *gorm.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) InTx(ctx context.Context, f auth.TxF) error {
	tx := s.db.WithContext(ctx).Begin()
	err := tx.Error
	if err != nil {
		return err
	}
	defer tx.Rollback()
	agg := NewPostgresStore(tx)
	err = f(ctx, agg)
	if err != nil {
		return err
	}
	return tx.Commit().Error
}
