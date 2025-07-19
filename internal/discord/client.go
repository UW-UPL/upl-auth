package discord

import (
	"fmt"
	"net/http"
	"go-forth/internal/constants"
)

type Client struct {
	token   string
	guildID string
	roleID  string
}

func NewClient(token, guildID, roleID string) *Client {
	return &Client{
		token:   token,
		guildID: guildID,
		roleID:  roleID,
	}
}

func (c *Client) IsConfigured() bool {
	return c.token != "" && c.guildID != "" && c.roleID != ""
}

func (c *Client) AssignRole(discordUserID string) error {
	if !c.IsConfigured() {
		return fmt.Errorf("discord client not configured")
	}

	url := fmt.Sprintf("%s/guilds/%s/members/%s/roles/%s",
		constants.DiscordAPIBase, c.guildID, discordUserID, c.roleID)

	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", constants.DiscordBotPrefix+c.token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("discord API error: status %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) RemoveRole(discordUserID string) error {
	if !c.IsConfigured() {
		return fmt.Errorf("discord client not configured")
	}

	url := fmt.Sprintf("%s/guilds/%s/members/%s/roles/%s",
		constants.DiscordAPIBase, c.guildID, discordUserID, c.roleID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", constants.DiscordBotPrefix+c.token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("discord API error: status %d", resp.StatusCode)
	}

	return nil
}
