package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"go-forth/internal/auth"
	"go-forth/internal/constants"
	"go-forth/internal/database"
	"go-forth/internal/discord"

	"github.com/bwmarrin/discordgo"
)

type Config struct {
	OAuthClientID     string
	OAuthClientSecret string
	JWTSecret         string
	DatabaseURL       string
	BaseURL           string
	DiscordToken      string
	DiscordGuildID    string
	DiscordRoleID     string
	AutoApproveDomains string
}

func (c *Config) GetOAuthClientID() string     { return c.OAuthClientID }
func (c *Config) GetOAuthClientSecret() string { return c.OAuthClientSecret }
func (c *Config) GetJWTSecret() string         { return c.JWTSecret }
func (c *Config) GetBaseURL() string           { return c.BaseURL }
func (c *Config) GetAutoApproveDomains() string { return c.AutoApproveDomains }

func main() {
	config := loadConfig()

	db, err := database.Connect(config.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	discordClient := discord.NewClient(config.DiscordToken, config.DiscordGuildID, config.DiscordRoleID)
	authService := auth.NewService(db, discordClient, config)

	dg, err := discordgo.New(constants.DiscordBotPrefix + config.DiscordToken)
	if err != nil {
		log.Fatal("Error creating Discord session: ", err)
	}

	botHandler := NewBotHandler(authService, config.BaseURL)

	dg.AddHandler(func(s *discordgo.Session, i *discordgo.InteractionCreate) {
		if i.ApplicationCommandData().Name == "verify" {
			botHandler.HandleVerifyCommand(s, i)
		}
	})

	dg.AddHandler(func(s *discordgo.Session, r *discordgo.Ready) {
		log.Printf("Discord bot ready! Logged in as: %v#%v", s.State.User.Username, s.State.User.Discriminator)
	})

	dg.Identify.Intents = discordgo.IntentsGuildMessages

	err = dg.Open()
	if err != nil {
		log.Fatal("Error opening Discord connection: ", err)
	}
	defer dg.Close()

	commands := []*discordgo.ApplicationCommand{
		{
			Name:        "verify",
			Description: "Verify your identity with OAuth",
		},
	}

	log.Println("Registering Discord slash commands...")
	for _, command := range commands {
		_, err := dg.ApplicationCommandCreate(dg.State.User.ID, config.DiscordGuildID, command)
		if err != nil {
			log.Printf("Cannot create '/%v' command: %v", command.Name, err)
			log.Printf("Make sure bot was invited with 'applications.commands' scope")
		} else {
			log.Printf("Successfully registered command: /%v", command.Name)
		}
	}

	log.Println("Bot is ready! Users can use: /verify")
	log.Println("Press CTRL+C to exit.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down Discord bot...")

	registeredCommands, err := dg.ApplicationCommands(dg.State.User.ID, config.DiscordGuildID)
	if err != nil {
		log.Printf("Could not fetch registered commands: %v", err)
	} else {
		for _, command := range registeredCommands {
			err := dg.ApplicationCommandDelete(dg.State.User.ID, config.DiscordGuildID, command.ID)
			if err != nil {
				log.Printf("Could not delete '%v' command: %v", command.Name, err)
			}
		}
	}
}

func loadConfig() *Config {
	config := &Config{
		OAuthClientID:     getEnv("OAUTH_CLIENT_ID", ""),
		OAuthClientSecret: getEnv("OAUTH_CLIENT_SECRET", ""),
		JWTSecret:         getEnv("JWT_SECRET", ""),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://postgres:password@localhost:5432/go_forth?sslmode=disable"),
		BaseURL:           getEnv("BASE_URL", "http://localhost:8080"),
		DiscordToken:      getEnv("DISCORD_TOKEN", ""),
		DiscordGuildID:    getEnv("DISCORD_GUILD_ID", ""),
		DiscordRoleID:     getEnv("DISCORD_ROLE_ID", ""),
		AutoApproveDomains: getEnv("AUTO_APPROVE_DOMAINS", ""),
	}

	if config.DiscordToken == "" {
		log.Fatal("DISCORD_TOKEN environment variable is required")
	}
	if config.DiscordGuildID == "" {
		log.Fatal("DISCORD_GUILD_ID environment variable is required")
	}
	if config.JWTSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

type BotHandler struct {
	authService *auth.Service
	baseURL     string
}

func NewBotHandler(authService *auth.Service, baseURL string) *BotHandler {
	return &BotHandler{
		authService: authService,
		baseURL:     baseURL,
	}
}

func (h *BotHandler) HandleVerifyCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	discordID := i.Member.User.ID
	discordUsername := i.Member.User.Username

	authURL := h.baseURL + constants.AuthRouteGroup + constants.LoginRoute + "?discord_id=" + discordID

	log.Printf("Generated verification URL for %s (ID: %s)", discordUsername, discordID)

	embed := &discordgo.MessageEmbed{
		Title:       "Identity Verification",
		Description: "Click the link below to verify your identity:",
		Color:       0x0066cc,
		Fields: []*discordgo.MessageEmbedField{
			{
				Name:   "What happens next?",
				Value:  "1. Click the verification link\n2. Sign in with your account\n3. Get automatically verified and receive your role!",
				Inline: false,
			},
			{
				Name:   "Privacy Note",
				Value:  "This link is unique to your Discord account and expires in 10 minutes.",
				Inline: false,
			},
		},
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Discord Authentication",
		},
	}

	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
			Components: []discordgo.MessageComponent{
				discordgo.ActionsRow{
					Components: []discordgo.MessageComponent{
						discordgo.Button{
							Style: discordgo.LinkButton,
							Label: "Verify Identity",
							URL:   authURL,
						},
					},
				},
			},
			Flags: discordgo.MessageFlagsEphemeral,
		},
	})

	if err != nil {
		log.Printf("Error responding to verify command: %v", err)
		return
	}

	log.Printf("Sent verification link to %s", discordUsername)
}
