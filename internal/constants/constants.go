package constants

import "time"

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
)

const (
	OAuthStateCookieName     = "oauth_state"
	OAuthStateCookieDuration = 10 * time.Minute
	OAuthStateLength         = 32
	OAuthDiscordSeparator    = ":discord:"
)

const (
	DiscordAPIBase = "https://discord.com/api/v10"
	DiscordBotPrefix = "Bot "
)

const (
	AuthRouteGroup  = "/auth"
	AdminRouteGroup = "/admin"
)

const (
	LoginRoute        = "/login"
	CallbackRoute     = "/callback"
	LinkDiscordRoute  = "/link-discord"
	PendingUsersRoute = "/pending-users"
	ApproveUserRoute  = "/approve-user"
	HealthRoute       = "/health"
	AdminRoute        = "/admin"
)

const (
	JWTExpirationDays = 7
)

const (
	MaxOpenConns = 25
	MaxIdleConns = 25
)

const (
	MsgAuthStateError    = "Authentication state lost. Please try verification again."
	MsgStateMismatch     = "Authentication state mismatch. Please try verification again."
	MsgMissingCode       = "Missing authorization code"
	MsgOAuthError        = "Failed to get user information from OAuth provider"
	MsgCreateUserError   = "Failed to create user account"
	MsgAccountRejected   = "Your account has been rejected. Please contact an administrator."
	MsgAccountPending    = "Account pending approval"
	MsgDiscordLinked     = "Discord account linked and role assigned successfully"
	MsgDiscordDuplicate  = "This Discord account is already linked to another user."
	MsgDiscordLinkError  = "Failed to link your Discord account. Please try again."
	MsgUnknownStatus     = "Unknown user status"
	MsgUserApproved      = "User status updated successfully"
)

const (
	ServiceName = "go-forth"
)

const (
	AutoApprovedBy = "auto-approved"
)

const (
	AdminCookieName = "admin_token"
	AdminCookieDuration = 24 * time.Hour
)
