# Deployment Guide

## Quick Deploy (Recommended)

The fastest way to get running on any fresh Linux server:

```bash
curl -fsSL https://raw.githubusercontent.com/osintph/darkweb-scanner/main/deploy.sh | sudo bash
```

This installs Docker, clones the repo, configures Tor, and starts all services automatically.

---

## SSL / HTTPS

The dashboard runs behind an Nginx reverse proxy with SSL enabled by default.

### Self-Signed Certificate (default)

If you do not set a domain, a self-signed certificate is generated automatically. The dashboard will be accessible at `https://YOUR_SERVER_IP` but browsers will show a "Not secure" warning. Traffic is still encrypted.

### Trusted SSL with Let's Encrypt (recommended for production)

You need a domain name pointed at your server's public IP.

**Option A — Set domain at deploy time:**
```bash
DOMAIN=scanner.yourdomain.com SSL_EMAIL=you@example.com sudo bash deploy.sh
```

**Option B — Set domain after deployment (without redeploying):**
```bash
sudo bash ~/darkweb-scanner/scripts/configure-ssl.sh
```

The helper prompts you interactively — your domain and email are stored only in `.env` on the server, never in git.

### DNS Setup (Cloudflare or any provider)

1. Log into your DNS provider
2. Add an **A record**:
   - Name: `scanner` (or any subdomain you want)
   - Value: your server's public IP
   - TTL: Auto
3. Wait 1-5 minutes for DNS to propagate
4. Run `sudo bash ~/darkweb-scanner/scripts/configure-ssl.sh`

**Cloudflare users:** Set the proxy status to **DNS only** (grey cloud, not orange) for the A record. Let's Encrypt needs to reach your server directly for certificate validation. You can re-enable the Cloudflare proxy after the cert is issued if desired.

### Free Domain Options

If you do not have a domain yet:

| Option | Cost | Notes |
|--------|------|-------|
| Namecheap / Cloudflare Registrar | ~$10/year | Most reliable |
| DuckDNS | Free | `yourname.duckdns.org` subdomains |
| Freenom | Free | `.tk`, `.ml` domains — less reliable |

**DuckDNS quick setup:**
1. Go to [duckdns.org](https://www.duckdns.org) and sign in
2. Create a subdomain and point it to your server IP
3. Use `yourname.duckdns.org` as your `DOMAIN`

---

## Production Setup on Ubuntu 22.04 VPS

### 1. Initial Server Hardening

```bash
apt update && apt upgrade -y

# Create a non-root user
adduser scanner
usermod -aG sudo,docker scanner

# Harden SSH
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
systemctl restart sshd

# Firewall
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
curl -fsSL https://raw.githubusercontent.com/osintph/darkweb-scanner/main/deploy.sh | sudo bash
```

### 3. Configure SSL

```bash
sudo bash ~/darkweb-scanner/scripts/configure-ssl.sh
```

### 4. Schedule Scans

```bash
INSTALL_TIMER=1 sudo bash ~/darkweb-scanner/deploy.sh
```

---

## Environment Variables Reference

All configuration lives in `.env` in the repo root. Never commit this file.

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | (empty) | Public domain for Let's Encrypt SSL |
| `SSL_EMAIL` | (empty) | Email for Let's Encrypt registration |
| `DASHBOARD_SECRET_KEY` | (generated) | Flask session secret |
| `TOR_CONTROL_PASSWORD` | (generated) | Tor control port password |
| `DATABASE_URL` | SQLite | Database connection string |
| `ALERT_WEBHOOK_URL` | (empty) | Slack/Discord webhook for alerts |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## Updating

```bash
cd ~/darkweb-scanner
git pull
docker compose build --no-cache
docker compose up -d
```

## Troubleshooting

**Tor not connecting:**
```bash
docker compose logs tor | grep Bootstrapped
make check-tor
```

**Dashboard not loading:**
```bash
docker compose logs dashboard
docker compose logs nginx
```

**Certificate issues:**
```bash
docker compose logs nginx
sudo bash ~/darkweb-scanner/scripts/configure-ssl.sh
```

**Full restart:**
```bash
docker compose down && docker compose up -d
```
