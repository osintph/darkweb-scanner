# Deployment Guide

## Quick Deploy (Recommended)

The fastest way to get running on any fresh Linux server:

```bash
curl -fsSL https://raw.githubusercontent.com/osintph/darkweb-scanner/main/deploy.sh -o /tmp/deploy.sh && sudo bash /tmp/deploy.sh
```

This installs Docker, clones the repo, configures Tor, generates secrets, and starts all services automatically.

---

## SSL / HTTPS

The dashboard runs behind an Nginx reverse proxy with SSL enabled by default.

### Self-Signed Certificate (default)

If you do not set a domain, a self-signed certificate is generated automatically. The dashboard will be accessible at `https://YOUR_SERVER_IP` but browsers will show a "Not secure" warning. Traffic is still encrypted.

### Trusted SSL with Let's Encrypt (recommended for production)

You need a domain name pointed at your server's public IP.

**Option A — Set domain at deploy time:**
```bash
DOMAIN=scanner.yourdomain.com SSL_EMAIL=you@example.com sudo bash /tmp/deploy.sh
```

**Option B — Set domain after deployment:**
```bash
sudo bash ~/darkweb-scanner/scripts/configure-ssl.sh
```

### DNS Setup

1. Add an **A record** at your DNS provider pointing to your server's public IP
2. **Cloudflare users:** Set proxy status to **DNS only** (grey cloud) during cert issuance

---

## Production Setup on Ubuntu 22.04 VPS

### 1. Initial Server Hardening

```bash
apt update && apt upgrade -y
adduser scanner
usermod -aG sudo,docker scanner
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
systemctl restart sshd
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

### 2. Deploy

```bash
su - scanner
curl -fsSL https://raw.githubusercontent.com/osintph/darkweb-scanner/main/deploy.sh -o /tmp/deploy.sh && \
  DOMAIN=scanner.yourdomain.com SSL_EMAIL=you@example.com sudo bash /tmp/deploy.sh
```

### 3. Configure API keys

```bash
nano ~/darkweb-scanner/.env
```

---

## Environment Variables Reference

All configuration lives in `.env`. **Never commit this file.**

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | (empty) | Public domain for Let's Encrypt SSL |
| `SSL_EMAIL` | (empty) | Email for Let's Encrypt registration |
| `DASHBOARD_SECRET_KEY` | (auto-generated) | Flask session secret |
| `TOR_CONTROL_PASSWORD` | (auto-generated) | Tor control port password |
| `DATABASE_URL` | SQLite | SQLite or PostgreSQL connection string |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

### Alerting

| Variable | Description |
|----------|-------------|
| `ALERT_WEBHOOK_URL` | Slack/Discord webhook for keyword hit alerts |
| `SMTP_HOST` / `SMTP_PORT` | SMTP server for email alerts |
| `SMTP_USER` / `SMTP_PASSWORD` | SMTP credentials |
| `ALERT_EMAIL_FROM` / `ALERT_EMAIL_TO` | Alert email addresses |

### Daily Digest (Mailgun)

| Variable | Description |
|----------|-------------|
| `MAILGUN_API_KEY` | Mailgun API key — required for digest delivery |
| `MAILGUN_DOMAIN` | Your Mailgun sending domain |
| `MAILGUN_FROM` | Sender display name and address |

### Threat Intelligence Feeds

| Variable | Description |
|----------|-------------|
| `OTX_API_KEY` | AlienVault OTX API key — free at otx.alienvault.com |

### IP Investigation

| Variable | Description |
|----------|-------------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB — free tier: 1,000 checks/day |
| `VIRUSTOTAL_API_KEY` | VirusTotal — free tier: 4 req/min |

### Telegram Scraper

| Variable | Default | Description |
|----------|---------|-------------|
| `TELEGRAM_API_ID` | (empty) | From my.telegram.org/apps |
| `TELEGRAM_API_HASH` | (empty) | From my.telegram.org/apps |
| `TELEGRAM_CHANNELS` | (empty) | Comma-separated channel usernames (no @) |
| `TELEGRAM_SESSION_PATH` | `/app/data/telegram.session` | Session file path |
| `TELEGRAM_LIMIT_PER_CHANNEL` | `200` | Max messages per channel |

### OAuth (optional)

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth credentials |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth credentials |

---

## Daily Digest Setup

The digest sends curated threat intelligence every morning at 08:00 PHT.

**1. Configure Mailgun** (free tier: 1,000 emails/month at mailgun.com)

**2. Configure OTX** — free API key at otx.alienvault.com

**3. Add subscribers** via dashboard (Settings → Digest → Subscribers)

**4. Schedule with cron:**
```bash
0 0 * * * cd ~/darkweb-scanner && docker compose exec -T dashboard \
  python -c "from darkweb_scanner.digest import send_digest; from darkweb_scanner.storage import Storage; send_digest(Storage())"
```

---

## DNS Reconnaissance

No additional setup required. Uses free public sources (crt.sh, HackerTarget, ip-api.com). The `dnspython` package is included in default dependencies.

---

## Updating

```bash
cd ~/darkweb-scanner
git pull
docker compose build --no-cache
docker compose up -d
```

---

## Troubleshooting

**Tor not connecting:** `docker compose logs tor | grep Bootstrapped`

**Dashboard not loading:** `docker compose logs dashboard`

**Digest not sending:** Check `MAILGUN_API_KEY` is set in `.env`

**Full restart:** `docker compose down && docker compose up -d`
