package auth

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"go-forth/internal/constants"
	"go-forth/internal/discord"
	"go-forth/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type Service struct {
	db            *sql.DB
	discordClient *discord.Client
	oauth         *OAuthConfig
	jwtSecret     []byte
	autoApproveDomains []string
}

type Config interface {
	GetOAuthClientID() string
	GetOAuthClientSecret() string
	GetJWTSecret() string
	GetBaseURL() string
	GetAutoApproveDomains() string
}

func NewService(db *sql.DB, discordClient *discord.Client, config Config) *Service {
	oauth := NewOAuthConfig(
		config.GetOAuthClientID(),
		config.GetOAuthClientSecret(),
		config.GetBaseURL(),
	)

	var autoApproveDomains []string
	if domains := config.GetAutoApproveDomains(); domains != "" {
		autoApproveDomains = strings.Split(domains, ",")
		for i, domain := range autoApproveDomains {
			autoApproveDomains[i] = strings.TrimSpace(domain)
		}
	}

	return &Service{
		db:            db,
		discordClient: discordClient,
		oauth:         oauth,
		jwtSecret:     []byte(config.GetJWTSecret()),
		autoApproveDomains: autoApproveDomains,
	}
}

func (s *Service) GetOAuthURL(state string) string {
	return s.oauth.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (s *Service) CreateOrUpdateUser(oauthUser *models.OAuthUserInfo) (*models.User, error) {
	user, err := s.getUserByOAuthID(oauthUser.ID)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if err == sql.ErrNoRows {
		return s.createUser(oauthUser)
	}

	return user, nil
}

func (s *Service) getUserByID(userID int) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, email, first_name, last_name, oauth_id, discord_id, status, join_reason, created_at, approved_at, approved_by
		FROM users WHERE id = $1
	`
	err := s.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Email, &user.FirstName, &user.LastName,
		&user.OAuthID, &user.DiscordID, &user.Status, &user.JoinReason, &user.CreatedAt, &user.ApprovedAt, &user.ApprovedBy,
	)
	return user, err
}

func (s *Service) GenerateJWT(user *models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    user.ID,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"status":     user.Status,
		"exp":        time.Now().Add(time.Hour * 24 * constants.JWTExpirationDays).Unix(),
	})

	return token.SignedString(s.jwtSecret)
}

func (s *Service) VerifyJWT(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
}

func (s *Service) LinkDiscordAccount(userID int, discordID string) error {
	var existingUserID int
	checkQuery := `SELECT id FROM users WHERE discord_id = $1 AND id != $2`
	err := s.db.QueryRow(checkQuery, discordID, userID).Scan(&existingUserID)

	if err == nil {
		return fmt.Errorf("discord account already linked to another user")
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check existing discord link: %w", err)
	}

	query := `UPDATE users SET discord_id = $1 WHERE id = $2`
	_, err = s.db.Exec(query, discordID, userID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return fmt.Errorf("discord account already linked to another user")
		}
		return fmt.Errorf("failed to link discord account: %w", err)
	}

	if s.discordClient.IsConfigured() {
		if err := s.discordClient.AssignRole(discordID); err != nil {
			log.Printf("Failed to assign Discord role to %s: %v", discordID, err)
			return fmt.Errorf("failed to assign discord role: %w", err)
		}
	}

	return nil
}

func (s *Service) GetPendingUsers() ([]models.User, error) {
	query := `
		SELECT id, email, first_name, last_name, oauth_id, discord_id, status, join_reason, created_at, approved_at, approved_by
		FROM users WHERE status = $1
		ORDER BY created_at DESC
	`
	rows, err := s.db.Query(query, constants.StatusPending)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending users: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName,
			&user.OAuthID, &user.DiscordID, &user.Status, &user.JoinReason, &user.CreatedAt, &user.ApprovedAt, &user.ApprovedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	return users, nil
}

func (s *Service) UpdateUserStatus(userID int, status string, approvedBy string) error {
	currentUser, err := s.getUserByID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if currentUser.Status == constants.StatusRejected && status == constants.StatusApproved {
		return fmt.Errorf("cannot approve a rejected user")
	}

	query := `
		UPDATE users
		SET status = $1, approved_at = $2, approved_by = $3
		WHERE id = $4
	`
	var approvedAt *time.Time
	if status == constants.StatusApproved {
		now := time.Now()
		approvedAt = &now
	}

	_, err = s.db.Exec(query, status, approvedAt, approvedBy, userID)
	if err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}

	return nil
}

func (s *Service) saveDiscordIDForUser(userID int, discordID string) error {
	var existingUser struct {
		ID    int
		Email string
	}
	checkQuery := `SELECT id, email FROM users WHERE discord_id = $1 AND id != $2`
	err := s.db.QueryRow(checkQuery, discordID, userID).Scan(&existingUser.ID, &existingUser.Email)

	if err == nil {
		log.Printf("Discord ID %s already linked to user %d (%s), cannot link to user %d",
			discordID, existingUser.ID, existingUser.Email, userID)
		return fmt.Errorf("discord account already linked to another user")
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check existing discord link: %w", err)
	}

	query := `UPDATE users SET discord_id = $1 WHERE id = $2`
	_, err = s.db.Exec(query, discordID, userID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return fmt.Errorf("discord account already linked to another user")
		}
		return fmt.Errorf("failed to save discord ID: %w", err)
	}
	return nil
}

func (s *Service) updateUserJoinReason(userID int, joinReason string) error {
	query := `UPDATE users SET join_reason = $1 WHERE id = $2`
	_, err := s.db.Exec(query, joinReason, userID)
	if err != nil {
		return fmt.Errorf("failed to update join reason: %w", err)
	}
	return nil
}

func (s *Service) isAutoApproveEmail(email string) bool {
	if len(s.autoApproveDomains) == 0 {
		return false
	}

	lowercaseEmail := strings.ToLower(email)
	for _, domain := range s.autoApproveDomains {
		if strings.HasSuffix(lowercaseEmail, strings.ToLower(domain)) {
			return true
		}
	}
	return false
}

func (s *Service) getUserByDiscordID(discordID string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, email, first_name, last_name, oauth_id, discord_id, status, join_reason, created_at, approved_at, approved_by
		FROM users WHERE discord_id = $1
	`
	err := s.db.QueryRow(query, discordID).Scan(
		&user.ID, &user.Email, &user.FirstName, &user.LastName,
		&user.OAuthID, &user.DiscordID, &user.Status, &user.JoinReason, &user.CreatedAt, &user.ApprovedAt, &user.ApprovedBy,
	)
	return user, err
}

func (s *Service) getUserByOAuthID(oauthID string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, email, first_name, last_name, oauth_id, discord_id, status, join_reason, created_at, approved_at, approved_by
		FROM users WHERE oauth_id = $1
	`
	err := s.db.QueryRow(query, oauthID).Scan(
		&user.ID, &user.Email, &user.FirstName, &user.LastName,
		&user.OAuthID, &user.DiscordID, &user.Status, &user.JoinReason, &user.CreatedAt, &user.ApprovedAt, &user.ApprovedBy,
	)
	return user, err
}

func (s *Service) createUser(oauthUser *models.OAuthUserInfo) (*models.User, error) {
	status := constants.StatusPending
	var approvedAt *time.Time
	var approvedBy *string

	if s.isAutoApproveEmail(oauthUser.Email) {
		status = constants.StatusApproved
		now := time.Now()
		approvedAt = &now
		approvedByStr := constants.AutoApprovedBy
		approvedBy = &approvedByStr
		log.Printf("Auto-approved user: %s", oauthUser.Email)
	}

	user := &models.User{
		Email:      oauthUser.Email,
		FirstName:  oauthUser.GivenName,
		LastName:   oauthUser.FamilyName,
		OAuthID:    oauthUser.ID,
		Status:     status,
		ApprovedAt: approvedAt,
		ApprovedBy: approvedBy,
	}

	query := `
		INSERT INTO users (email, first_name, last_name, oauth_id, discord_id, status, join_reason, approved_at, approved_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at
	`
	err := s.db.QueryRow(query, user.Email, user.FirstName, user.LastName,
		user.OAuthID, user.DiscordID, user.Status, user.JoinReason, user.ApprovedAt, user.ApprovedBy).Scan(&user.ID, &user.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}
