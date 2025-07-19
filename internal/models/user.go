package models

import "time"

type User struct {
	ID          int       `json:"id" db:"id"`
	Email       string    `json:"email" db:"email"`
	FirstName   string    `json:"first_name" db:"first_name"`
	LastName    string    `json:"last_name" db:"last_name"`
	GoogleID    string    `json:"google_id" db:"google_id"`
	DiscordID   *string   `json:"discord_id,omitempty" db:"discord_id"`
	Status      string    `json:"status" db:"status"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty" db:"approved_at"`
	ApprovedBy  *string   `json:"approved_by,omitempty" db:"approved_by"`
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}
