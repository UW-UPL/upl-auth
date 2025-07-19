package database

import (
	"database/sql"
	"fmt"
)

func Migrate(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		first_name VARCHAR(100) NOT NULL,
		last_name VARCHAR(100) NOT NULL,
		google_id VARCHAR(100) UNIQUE NOT NULL,
		discord_id VARCHAR(100) UNIQUE,
		status VARCHAR(20) DEFAULT 'pending',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		approved_at TIMESTAMP,
		approved_by VARCHAR(255)
	);

	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
	CREATE INDEX IF NOT EXISTS idx_users_discord_id ON users(discord_id);
	CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
	`

	if _, err := db.Exec(query); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}
