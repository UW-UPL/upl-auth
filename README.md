# go-forth

Discord authentication via Google OAuth for UPL members

## Setup

1. Create `docker-compose.yml`:
```yaml
services:
  app:
    image: ghcr.io/nicosalm/upl-auth:latest
    ports:
      - "8080:8080"
    env_file: .env
    environment:
      - DATABASE_URL=postgres://postgres:password@db:5432/discord_auth?sslmode=disable
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=discord_auth
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
    image: ghcr.io/nicosalm/upl-auth-bot:latest
    env_file: .env
    environment:
      - DATABASE_URL=postgres://postgres:password@db:5432/discord_auth?sslmode=disable
    depends_on:
      db:
        condition: service_healthy

volumes:
  postgres_data:
```

2. Create `.env`:
```bash
BASE_URL=https://yourdomain.com
ADMIN_PASSWORD=your-password
JWT_SECRET=any-32-char-string
GOOGLE_CLIENT_ID=from-google-console
GOOGLE_CLIENT_SECRET=from-google-console
DISCORD_BOT_TOKEN=from-discord-dev-portal
DISCORD_GUILD_ID=your-server-id
DISCORD_ROLE_ID=role-to-assign
```

3. Run:
```bash
docker-compose up -d
```

## Usage

- Users: Type `/verify` in Discord
- Admins: Visit `/admin` with your password

## Google OAuth

Add callback URL in Google Console: `https://yourdomain.com/auth/callback`

## Discord Bot

Needs Manage Roles permission and must be above the role it assigns.
