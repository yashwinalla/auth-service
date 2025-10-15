package main

import (
	"log"
	"os"
	"time"

	"github.com/hivemindd/auth-service/internal/store"
	"github.com/hivemindd/kit/env"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

// connectPostgres connects to postgres using GORM.
func connectPostgres(connString string) (*gorm.DB, error) {
	newLogger := gormLogger.Default.LogMode(gormLogger.Silent)

	if !env.IsProd() {
		newLogger = gormLogger.New(
			log.New(os.Stdout, "\n", log.LstdFlags), // io writer
			gormLogger.Config{
				SlowThreshold:             time.Second,     // Slow SQL threshold
				LogLevel:                  gormLogger.Info, // Log level
				IgnoreRecordNotFoundError: true,            // Ignore ErrRecordNotFound error for logger
				Colorful:                  false,           // Disable color
			},
		)
	}

	config := &gorm.Config{
		// setup GORM config.
		Logger:         newLogger,
		PrepareStmt:    false,
		TranslateError: true,
	}

	// TIP: there is a way to silence GORM logger. This might be useful in production.
	// Once logger is silenced it will not output executed SQL statements.

	db, err := gorm.Open(postgres.Open(connString), config)
	if err != nil {
		// It is ok to fail here, because database connection is essential for this service to work!
		return nil, err
	}

	rawDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	rawDB.SetMaxIdleConns(1)
	rawDB.SetMaxOpenConns(2)
	rawDB.SetConnMaxLifetime(time.Minute * 5)

	err = store.Migrate(db)
	if err != nil {
		return nil, err
	}

	return db, nil
}
