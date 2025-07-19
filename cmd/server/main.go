package main

import (
	"log"
	"os"
	"go-forth/internal/auth"
	"go-forth/internal/constants"
	"go-forth/internal/database"
	"go-forth/internal/discord"
	"github.com/gin-gonic/gin"
)

func main() {
	config := loadConfig()

	db, err := database.Connect(config.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	if err := database.Migrate(db); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	discordClient := discord.NewClient(config.DiscordBotToken, config.DiscordGuildID, config.DiscordRoleID)
	authService := auth.NewService(db, discordClient, config)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	setupCORS(router)
	authService.RegisterRoutes(router)
	setupStaticFiles(router)

	log.Printf("Server starting on port %s", config.Port)
	log.Fatal(router.Run(":" + config.Port))
}

type Config struct {
	GoogleClientID     string
	GoogleClientSecret string
	JWTSecret         string
	DatabaseURL       string
	BaseURL           string
	Port              string
	DiscordBotToken   string
	DiscordGuildID    string
	DiscordRoleID     string
}

func (c *Config) GetGoogleClientID() string     { return c.GoogleClientID }
func (c *Config) GetGoogleClientSecret() string { return c.GoogleClientSecret }
func (c *Config) GetJWTSecret() string         { return c.JWTSecret }
func (c *Config) GetBaseURL() string           { return c.BaseURL }

func loadConfig() *Config {
	config := &Config{
		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		JWTSecret:         getEnv("JWT_SECRET", ""),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://postgres:password@localhost:5432/discord_auth?sslmode=disable"),
		BaseURL:           getEnv("BASE_URL", "http://localhost:8080"),
		Port:              getEnv("PORT", "8080"),
		DiscordBotToken:   getEnv("DISCORD_BOT_TOKEN", ""),
		DiscordGuildID:    getEnv("DISCORD_GUILD_ID", ""),
		DiscordRoleID:     getEnv("DISCORD_ROLE_ID", ""),
	}

	if config.GoogleClientID == "" || config.GoogleClientSecret == "" || config.JWTSecret == "" {
		log.Fatal("Missing required environment variables: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SECRET")
	}

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func setupCORS(router *gin.Engine) {
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})
}

func setupStaticFiles(router *gin.Engine) {
	router.Static("/static", "./web/static")
	router.GET("/", func(c *gin.Context) {
		c.File("./web/static/index.html")
	})
	router.GET(constants.AdminRoute, func(c *gin.Context) {
		c.File("./web/static/admin.html")
	})
}
