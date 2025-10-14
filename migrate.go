package store

import (
	"github.com/hivemindd/auth-service/internal/model"
	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	entities := []interface{}{
		model.User{},
		model.LoginLog{},
		model.PasswordResetLog{},
	}
	for i := range entities {
		err := migrateModel(db, entities[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func migrateModel(db *gorm.DB, dst any) error {
	return db.Migrator().AutoMigrate(dst)
}
