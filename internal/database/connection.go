package database

import (
	"database/sql"
	"fmt"
	"go-forth/internal/constants"
	_ "github.com/lib/pq"
)

func Connect(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(constants.MaxOpenConns)
	db.SetMaxIdleConns(constants.MaxIdleConns)

	return db, nil
}
