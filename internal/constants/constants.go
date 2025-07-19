package constants

import "time"

// User status constants
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
)

// OAuth constants
const (
	OAuthStateCookieName     = "oauth_state"
	OAuthStateCookieDuration = 10 * time.Minute
	OAuthStateLength         = 32
	OAuthDiscordSeparator    = ":discord:"
)

// Discord constants
const (
	DiscordAPIBase = "https://discord.com/api/v10"
	DiscordBotPrefix = "Bot "
)

// Route groups
const (
	AuthRouteGroup  = "/auth"
	AdminRouteGroup = "/admin"
)

// Routes
const (
	LoginRoute        = "/login"
	CallbackRoute     = "/callback"
	LinkDiscordRoute  = "/link-discord"
	PendingUsersRoute = "/pending-users"
	ApproveUserRoute  = "/approve-user"
	HealthRoute       = "/health"
	AdminRoute        = "/admin"
)

// JWT constants
const (
	JWTExpirationDays = 7
)

// Database constants
const (
	MaxOpenConns = 25
	MaxIdleConns = 25
)

// HTTP status messages
const (
	MsgAuthStateError    = "Authentication state lost. Please try verification again."
	MsgStateMismatch     = "Authentication state mismatch. Please try verification again."
	MsgMissingCode       = "Missing authorization code"
	MsgGoogleError       = "Failed to get user information from Google"
	MsgCreateUserError   = "Failed to create user account"
	MsgAccountRejected   = "Your account has been rejected. Please contact an administrator."
	MsgAccountPending    = "Account pending approval"
	MsgDiscordLinked     = "Discord account linked and role assigned successfully"
	MsgDiscordDuplicate  = "This Discord account is already linked to another user."
	MsgDiscordLinkError  = "Failed to link your Discord account. Please try again."
	MsgUnknownStatus     = "Unknown user status"
	MsgUserApproved      = "User status updated successfully"
)

// Email domains
const (
	WiscEduDomain = "@wisc.edu"
)

// Service name
const (
	ServiceName = "go-forth"
)

// Auto-approval constants
const (
	AutoApprovedBy = "auto-approved"
)

// Admin authentication
const (
	AdminCookieName = "admin_token"
	AdminCookieDuration = 24 * time.Hour
)
