# go-forth

[![Docker](https://github.com/nicosalm/go-forth/actions/workflows/docker.yml/badge.svg)](https://github.com/nicosalm/go-forth/actions/workflows/docker.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Discord authentication via OAuth for community members

## What is this?

A Discord bot that verifies community members and gives them roles in Discord servers. Users prove their identity by logging in with their OAuth account (Google, etc).

## Deployment

**You only need two files to deploy this system:**

1. Create `.env`:
```bash
BASE_URL=https://yourdomain.com
ADMIN_PASSWORD=your-secure-password
ADMIN_PASSWORD_SALT=your-unique-salt-string
JWT_SECRET=your-32-character-jwt-secret-key
OAUTH_CLIENT_ID=your-oauth-client-id
OAUTH_CLIENT_SECRET=your-oauth-client-secret
DISCORD_TOKEN=your-discord-bot-token
DISCORD_GUILD_ID=your-discord-server-id
DISCORD_ROLE_ID=role-id-to-assign
AUTO_APPROVE_DOMAINS=@example.edu,@company.com
```

2. Create `docker-compose.yml`:
```yaml
services:
  app:
    image: ghcr.io/nicosalm/go-forth:latest
    ports:
      - "8080:8080"
    env_file: .env
    environment:
      - DATABASE_URL=postgres://postgres:password@db:5432/go_forth?sslmode=disable
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=go_forth
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  discord-bot:
    image: ghcr.io/nicosalm/go-forth:latest
    command: ["./bot"]
    env_file: .env
    environment:
      - DATABASE_URL=postgres://postgres:password@db:5432/go_forth?sslmode=disable
    depends_on:
      db:
        condition: service_healthy

volumes:
  postgres_data:
```

3. Run:
```bash
docker-compose up -d
```

## Usage
- **Users:** Type `/verify` in Discord → Click the link → Sign in → Get role assigned
- **Admins:** Visit `/admin` → Enter password → Approve/reject pending users

## Configuration
- **OAuth Provider:** Add callback URL: `https://yourdomain.com/auth/callback`
- **Discord Bot:** Needs "Manage Roles" permission
- **Auto-approve:** Set `AUTO_APPROVE_DOMAINS` for instant approval of specific email domains

## Security Features
- One Discord account per person
- One email per person
- Rejected users stay rejected
- Rate limiting on admin login
- Secure password comparison
- JWT token authentication

---

## Development

**Local development:**
```bash
git clone https://github.com/nicosalm/go-forth
cd go-forth
docker-compose -f docker-compose.dev.yml up --build
```

**Build from source:**
```bash
go build -o server ./cmd/server
go build -o bot ./cmd/discord-bot
```
