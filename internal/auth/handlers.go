package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"os"
	"fmt"

	"go-forth/internal/constants"
	"go-forth/internal/errors"
	"go-forth/internal/templates"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		attempts: make(map[string][]time.Time),
	}
}

func (rl *rateLimiter) checkLimit(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	var validAttempts []time.Time
	for _, attempt := range rl.attempts[key] {
		if attempt.After(cutoff) {
			validAttempts = append(validAttempts, attempt)
		}
	}

	if len(validAttempts) >= limit {
		rl.attempts[key] = validAttempts
		return false
	}

	rl.attempts[key] = append(validAttempts, now)
	return true
}

var adminRateLimiter = newRateLimiter()

func (s *Service) RegisterRoutes(router *gin.Engine) {
	auth := router.Group(constants.AuthRouteGroup)
	{
		auth.GET(constants.LoginRoute, s.handleLogin)
		auth.GET(constants.CallbackRoute, s.handleCallback)
		auth.POST(constants.LinkDiscordRoute, s.handleLinkDiscord)
		auth.POST("/submit-reason", s.handleSubmitReason)
	}

	admin := router.Group(constants.AdminRouteGroup)
	admin.Use(s.requireAdminAuth())
	{
		admin.GET(constants.PendingUsersRoute, s.handlePendingUsers)
		admin.POST(constants.ApproveUserRoute, s.handleApproveUser)
	}

	router.GET(constants.HealthRoute, s.handleHealth)
	router.POST("/admin/login", s.handleAdminLogin)
	router.POST("/admin/logout", s.handleAdminLogout)
}

func (s *Service) handleLogin(c *gin.Context) {
	discordID := c.Query("discord_id")

	state, err := s.oauth.GenerateState()
	if err != nil {
		errors.InternalServerError(c, "Failed to generate state")
		return
	}

	if discordID != "" {
		state = state + constants.OAuthDiscordSeparator + discordID
		log.Printf("Starting Discord verification flow for Discord ID: %s", discordID)
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		constants.OAuthStateCookieName,
		state,
		int(constants.OAuthStateCookieDuration.Seconds()),
		"/", "", false, true,
	)

	authURL := s.GetOAuthURL(state)

	if discordID != "" {
		c.Redirect(http.StatusTemporaryRedirect, authURL)
		return
	}

	c.JSON(http.StatusOK, gin.H{"auth_url": authURL})
}

func (s *Service) handleCallback(c *gin.Context) {
	if c.Query("pending") == "true" {
		templates.RenderPending(c, templates.PendingData{
			Email:     "Your application",
			FirstName: "",
			LastName:  "",
		})
		return
	}

	stateParam := c.Query("state")
	stateCookie, cookieErr := c.Cookie(constants.OAuthStateCookieName)

	if cookieErr != nil {
		log.Printf("OAuth state cookie missing: %v", cookieErr)
		errors.BadRequest(c, constants.MsgAuthStateError)
		return
	}

	if stateCookie != stateParam {
		log.Printf("OAuth state mismatch - Cookie: %s, Param: %s", stateCookie, stateParam)
		errors.BadRequest(c, constants.MsgStateMismatch)
		return
	}

	code := c.Query("code")
	if code == "" {
		errors.BadRequest(c, constants.MsgMissingCode)
		return
	}

	c.SetCookie(constants.OAuthStateCookieName, "", -1, "/", "", false, true)

	stateParts := strings.Split(stateCookie, constants.OAuthDiscordSeparator)
	var discordID string
	if len(stateParts) > 1 {
		discordID = stateParts[1]
		log.Printf("Processing Discord verification for Discord ID: %s", discordID)
	}

	oauthUser, err := s.oauth.GetUserInfo(context.Background(), code)
	if err != nil {
		log.Printf("OAuth GetUserInfo error: %v", err)
		if discordID != "" {
			templates.RenderError(c, templates.ErrorData{Message: constants.MsgOAuthError})
			return
		}
		errors.InternalServerError(c, "Failed to get user information")
		return
	}

	if discordID != "" {
		existingUser, err := s.getUserByDiscordID(discordID)
		if err == nil {
			log.Printf("Discord ID %s already linked to user %d (%s) with status %s", discordID, existingUser.ID, existingUser.Email, existingUser.Status)
			if existingUser.Status == constants.StatusRejected {
				templates.RenderError(c, templates.ErrorData{Message: "This Discord account has been rejected and cannot be used for verification."})
			} else {
				templates.RenderError(c, templates.ErrorData{Message: constants.MsgDiscordDuplicate})
			}
			return
		} else if err != sql.ErrNoRows {
			log.Printf("Error checking Discord ID: %v", err)
			templates.RenderError(c, templates.ErrorData{Message: "Failed to verify Discord account"})
			return
		}
	}

	user, err := s.CreateOrUpdateUser(oauthUser)
	if err != nil {
		log.Printf("CreateOrUpdateUser error: %v", err)
		if discordID != "" {
			if strings.Contains(err.Error(), "email already registered") {
				templates.RenderError(c, templates.ErrorData{Message: "This email address is already registered with another account."})
				return
			}
			if strings.Contains(err.Error(), "email has been rejected") {
				templates.RenderError(c, templates.ErrorData{Message: "This email has been rejected and cannot be used for verification."})
				return
			}
			templates.RenderError(c, templates.ErrorData{Message: constants.MsgCreateUserError})
			return
		}
		errors.InternalServerError(c, constants.MsgCreateUserError)
		return
	}

	switch user.Status {
	case constants.StatusRejected:
		if discordID != "" {
			templates.RenderError(c, templates.ErrorData{Message: constants.MsgAccountRejected})
			return
		}
		errors.Forbidden(c, "Access denied")
		return

	case constants.StatusPending:
		if discordID != "" {
			err := s.saveDiscordIDForUser(user.ID, discordID)
			if err != nil {
				log.Printf("Failed to save Discord ID for pending user %d: %v", user.ID, err)
			} else {
				log.Printf("Saved Discord ID %s for pending user %d (%s)", discordID, user.ID, user.Email)
			}

			isAutoApprove := s.isAutoApproveEmail(user.Email)
			hasReason := user.JoinReason != nil && *user.JoinReason != ""
			log.Printf("User %s - isAutoApprove: %v, hasReason: %v, JoinReason: %v", user.Email, isAutoApprove, hasReason, user.JoinReason)

			if !isAutoApprove && !hasReason {
				log.Printf("Non-auto-approve user %s (%d) needs join reason", user.Email, user.ID)
				templates.RenderJoinReason(c, templates.JoinReasonData{
					Email:     user.Email,
					FirstName: user.FirstName,
					LastName:  user.LastName,
					UserID:    user.ID,
				})
				return
			}

			templates.RenderPending(c, templates.PendingData{
				Email:     user.Email,
				FirstName: user.FirstName,
				LastName:  user.LastName,
			})
			return
		}
		c.JSON(http.StatusAccepted, gin.H{
			"message": constants.MsgAccountPending,
			"status":  constants.StatusPending,
			"user": gin.H{
				"email": user.Email,
				"name":  user.FirstName + " " + user.LastName,
			},
		})
		return

	case constants.StatusApproved:
		if discordID != "" {
			if user.DiscordID != nil && *user.DiscordID != "" && *user.DiscordID != discordID {
				log.Printf("User %d already has Discord ID %s, cannot change to %s", user.ID, *user.DiscordID, discordID)
				templates.RenderError(c, templates.ErrorData{Message: "This account is already linked to a different Discord ID."})
				return
			}

			err := s.LinkDiscordAccount(user.ID, discordID)
			if err != nil {
				log.Printf("Failed to link Discord account for user %d: %v", user.ID, err)
				if strings.Contains(err.Error(), "already linked") {
					templates.RenderError(c, templates.ErrorData{Message: constants.MsgDiscordDuplicate})
				} else {
					templates.RenderError(c, templates.ErrorData{Message: constants.MsgDiscordLinkError})
				}
				return
			}
			templates.RenderSuccess(c, templates.SuccessData{
				Email:     user.Email,
				FirstName: user.FirstName,
				LastName:  user.LastName,
			})
			return
		}

		token, err := s.GenerateJWT(user)
		if err != nil {
			errors.InternalServerError(c, "Failed to generate token")
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Authentication successful",
			"token":   token,
			"user":    user,
		})
		return

	default:
		if discordID != "" {
			templates.RenderError(c, templates.ErrorData{Message: constants.MsgUnknownStatus})
			return
		}
		errors.InternalServerError(c, constants.MsgUnknownStatus)
		return
	}
}

func (s *Service) handleSubmitReason(c *gin.Context) {
	var req struct {
		UserID     int    `json:"user_id" binding:"required"`
		JoinReason string `json:"join_reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors.BadRequest(c, "Invalid request")
		return
	}

	if len(req.JoinReason) < 10 || len(req.JoinReason) > 1000 {
		errors.BadRequest(c, "Join reason must be between 10 and 1000 characters")
		return
	}

	err := s.updateUserJoinReason(req.UserID, req.JoinReason)
	if err != nil {
		errors.InternalServerError(c, "Failed to update join reason")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Join reason submitted successfully"})
}

func (s *Service) handleLinkDiscord(c *gin.Context) {
	var req struct {
		Token     string `json:"token" binding:"required"`
		DiscordID string `json:"discord_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors.BadRequest(c, "Invalid request")
		return
	}

	token, err := s.VerifyJWT(req.Token)
	if err != nil || !token.Valid {
		errors.Unauthorized(c, "Invalid token")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		errors.Unauthorized(c, "Invalid token claims")
		return
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		errors.Unauthorized(c, "Invalid user ID in token")
		return
	}

	status, ok := claims["status"].(string)
	if !ok || status != constants.StatusApproved {
		errors.Forbidden(c, "User not approved")
		return
	}

	if err := s.LinkDiscordAccount(int(userID), req.DiscordID); err != nil {
		errors.InternalServerError(c, "Failed to link Discord account")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": constants.MsgDiscordLinked,
	})
}

func (s *Service) handlePendingUsers(c *gin.Context) {
	users, err := s.GetPendingUsers()
	if err != nil {
		errors.InternalServerError(c, "Failed to retrieve pending users")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"count": len(users),
	})
}

func (s *Service) handleApproveUser(c *gin.Context) {
	var req struct {
		UserID     int    `json:"user_id" binding:"required"`
		Status     string `json:"status" binding:"required"`
		ApprovedBy string `json:"approved_by" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		errors.BadRequest(c, "Invalid request")
		return
	}

	if req.Status != constants.StatusApproved && req.Status != constants.StatusRejected {
		errors.BadRequest(c, "Status must be 'approved' or 'rejected'")
		return
	}

	if err := s.UpdateUserStatus(req.UserID, req.Status, req.ApprovedBy); err != nil {
		errors.InternalServerError(c, "Failed to update user status")
		return
	}

	if req.Status == constants.StatusApproved {
		user, err := s.getUserByID(req.UserID)
		if err != nil {
			log.Printf("Failed to get user %d after approval: %v", req.UserID, err)
		} else if user.DiscordID != nil && *user.DiscordID != "" {
			if s.discordClient.IsConfigured() {
				if err := s.discordClient.AssignRole(*user.DiscordID); err != nil {
					log.Printf("Failed to auto-assign Discord role to user %d (Discord ID: %s): %v",
						req.UserID, *user.DiscordID, err)
				} else {
					log.Printf("AUTO-ASSIGNED Discord role to approved user %d (%s) with Discord ID %s",
						req.UserID, user.Email, *user.DiscordID)
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": constants.MsgUserApproved})
}

func (s *Service) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"service":   constants.ServiceName,
	})
}

func (s *Service) requireAdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie(constants.AdminCookieName)
		if err != nil || cookie == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if !s.isValidAdminToken(cookie) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Next()
	}
}

func (s *Service) handleAdminLogin(c *gin.Context) {
	clientIP := c.ClientIP()

	if !adminRateLimiter.checkLimit(clientIP, 5, 15*time.Minute) {
		time.Sleep(2 * time.Second)
		errors.TooManyRequests(c, "Too many login attempts")
		return
	}

	var req struct {
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		time.Sleep(500 * time.Millisecond)
		errors.BadRequest(c, "Invalid request")
		return
	}

	adminPasswordHash := s.getAdminPasswordHash()
	providedPasswordHash := s.hashPassword(req.Password)

	if subtle.ConstantTimeCompare([]byte(adminPasswordHash), []byte(providedPasswordHash)) != 1 {
		time.Sleep(500 * time.Millisecond)
		errors.Unauthorized(c, "Invalid password")
		return
	}

	token := s.generateAdminToken()

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		constants.AdminCookieName,
		token,
		int(constants.AdminCookieDuration.Seconds()),
		"/", "", false, true,
	)

	c.JSON(http.StatusOK, gin.H{"message": "Admin login successful"})
}

func (s *Service) handleAdminLogout(c *gin.Context) {
	c.SetCookie(constants.AdminCookieName, "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (s *Service) isValidAdminToken(token string) bool {
	expectedToken := s.generateAdminToken()
	return subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1
}

func (s *Service) generateAdminToken() string {
	passwordHash := s.getAdminPasswordHash()
	return fmt.Sprintf("admin-%s", passwordHash)
}

func (s *Service) hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password + s.getPasswordSalt()))
	return hex.EncodeToString(hash[:])
}

func (s *Service) getAdminPasswordHash() string {
	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		log.Fatal("ADMIN_PASSWORD environment variable is required")
	}
	return s.hashPassword(password)
}

func (s *Service) getPasswordSalt() string {
	salt := os.Getenv("ADMIN_PASSWORD_SALT")
	if salt == "" {
		log.Fatal("ADMIN_PASSWORD_SALT environment variable is required")
	}
	return salt
}
