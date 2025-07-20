package models

import "time"

type User struct {
	ID          int       `json:"id" db:"id"`
	Email       string    `json:"email" db:"email"`
	FirstName   string    `json:"first_name" db:"first_name"`
	LastName    string    `json:"last_name" db:"last_name"`
	OAuthID     string    `json:"oauth_id" db:"oauth_id"`
	DiscordID   *string   `json:"discord_id,omitempty" db:"discord_id"`
	Status      string    `json:"status" db:"status"`
	JoinReason  *string   `json:"join_reason,omitempty" db:"join_reason"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty" db:"approved_at"`
	ApprovedBy  *string   `json:"approved_by,omitempty" db:"approved_by"`
}

type OAuthUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}
