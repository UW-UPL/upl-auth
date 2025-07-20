# upl-discord-auth

Discord bot that verifies UW-Madison students and assigns roles in the UPL Discord server. Students authenticate with their Google accounts to prove they're real UW students.

> [!TIP]
> If you have questions about maintaining this repo, reach out to **salm@cs.wisc.edu** :D

## what is this?

The Undergraduate Projects Lab uses this system to keep our Discord server limited to actual UW students while staying open to alumni and friends of the lab. Students use `/verify` in Discord, sign in with Google, and automatically get the verified role.

## tldr; how it works

1. **Students:** Type `/verify` in Discord → Click link → Sign in with Google → Get role
2. **Auto-approval:** @wisc.edu and @cs.wisc.edu addresses get instant access
3. **Manual review:** Other domains need admin approval (24-48 hours)
4. **Admins:** Visit `/admin` to approve/reject pending users

## development

```bash
git clone https://github.com/UW-UPL/upl-discord-auth
cd upl-discord-auth
cp .env.example .env
# Fill in your config values
docker-compose up --build
```

## deployment

Set up your `.env` file and run:
```bash
docker-compose up -d
```

**required config:**
- Google OAuth credentials (for @wisc.edu authentication)
- Discord bot token and role IDs
- Admin password for user management
- Database connection

## security features we enforce:

- One Discord account per person
- One email per person
- Rejected users stay rejected
- Rate limiting on admin login
- UW email domain validation

---
*Based on [go-forth](https://github.com/nicosalm/go-forth) by `nicosalm`*

