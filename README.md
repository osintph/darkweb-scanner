# 🔍 Dark Web Scanner

> Keyword monitoring tool for `.onion` sites — built for security researchers and threat intelligence professionals.

[![CI](https://github.com/osintph/darkweb-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/osintph/darkweb-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](docker-compose.yml)

---

## ⚠️ Legal & Ethical Notice

This tool is intended **exclusively for lawful security research, threat intelligence, and brand monitoring** purposes. By using this software you confirm that:

- You are using it to monitor for mentions of your own organisation, brand, or infrastructure
- You are operating within the laws of your jurisdiction
- You will not use it to access, store, or distribute illegal content
- You accept full legal responsibility for how you operate the tool

See [LEGAL.md](LEGAL.md) for the full disclaimer.

---

## 🚀 Quick Deploy (fresh server — installs everything)
```bash
curl -fsSL https://raw.githubusercontent.com/osintph/darkweb-scanner/main/deploy.sh | sudo bash
```

Or clone first and run locally:
```bash
git clone https://github.com/osintph/darkweb-scanner
cd darkweb-scanner
sudo bash deploy.sh
```

Optional overrides:
```bash
INSTALL_DIR=/opt/darkweb-scanner sudo bash deploy.sh
DASHBOARD_PORT=9090 sudo bash deploy.sh
INSTALL_TIMER=1 sudo bash deploy.sh   # enable 6-hour scheduled scans
```

## What It Does

Dark Web Scanner crawls `.onion` sites through the Tor network and alerts you when your configured keywords appear. Useful for:

- **Brand monitoring** — detect mentions of your company, products, or domains
- **Credential leak detection** — get alerted when your organisation appears in breach discussions
- **Infrastructure monitoring** — watch for references to your IP ranges or hostnames
- **Threat intelligence** — track activity around specific threat actors or campaigns

---

## Quick Start

**Prerequisites:** Docker and Docker Compose installed.

```bash
# 1. Clone the repo
git clone https://github.com/osintph/darkweb-scanner
cd darkweb-scanner

# 2. Set up config files
make setup

# 3. Edit your keywords and seed URLs
nano config/keywords.yaml
nano config/seeds.txt

# 4. Configure environment
nano .env   # set TOR_CONTROL_PASSWORD and optionally alerting

# 5. Start the dashboard (and Tor)
make run

# 6. Open the dashboard
open http://localhost:8080

# 7. Run a scan
make scan
```

That's it. Tor starts automatically inside Docker — no separate Tor installation needed.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Docker Network                       │
│                                                          │
│  ┌──────────┐    SOCKS5     ┌──────────────────────┐    │
│  │          │◄─────────────►│                      │    │
│  │   Tor    │               │  Scanner / Crawler   │    │
│  │  daemon  │               │                      │    │
│  │          │               └──────────┬───────────┘    │
│  └──────────┘                          │                 │
│                                        ▼                 │
│                              ┌──────────────────┐        │
│                              │  Keyword Scanner │        │
│                              └────────┬─────────┘        │
│                                       │                  │
│                              ┌────────▼─────────┐        │
│                              │  SQLite / Postgres│        │
│                              └────────┬─────────┘        │
│                                       │                  │
│  ┌──────────────────┐        ┌────────▼─────────┐        │
│  │    Dashboard     │◄───────│    Alerting      │        │
│  │  (Flask :8080)   │        │  Webhook / Email │        │
│  └──────────────────┘        └──────────────────┘        │
└─────────────────────────────────────────────────────────┘
```

---

## Configuration

### Keywords (`config/keywords.yaml`)

```yaml
keywords:
  brand_monitoring:
    - "your company name"
    - "yourdomain.com"
  threat_intel:
    - "credential dump"
    - "database leak"

settings:
  context_window: 200       # chars of surrounding context to capture
  case_sensitive: false
  alert_on_first_hit_only: true
```

### Seed URLs (`config/seeds.txt`)

One `.onion` URL per line. Start with Tor index sites from [Ahmia](https://ahmia.fi) to discover relevant seeds.

### Alerting (`.env`)

**Slack/Discord webhook:**
```ini
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
```

**Email:**
```ini
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_TO=alerts@yourcompany.com
```

---

## CLI Reference

```bash
# Run a scan
darkweb-scanner scan --seeds config/seeds.txt --keywords config/keywords.yaml

# Show statistics
darkweb-scanner stats

# Show recent hits
darkweb-scanner hits --limit 50

# Verify Tor is working
darkweb-scanner check-tor
```

Or via Docker:

```bash
make scan         # run a crawl
make stats        # show statistics
make hits         # show recent hits
make check-tor    # verify Tor
make logs         # tail all logs
```

---

## Development

```bash
# Set up dev environment
make dev-install

# Run unit tests
make test

# Lint and type check
make lint

# Auto-format
make format
```

See [docs/contributing.md](docs/contributing.md) for the full contribution guide.

---

## Deployment

See [docs/deployment.md](docs/deployment.md) for production deployment instructions including:
- Server hardening
- Systemd service setup
- Encrypted storage
- Backup strategies

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

Good first issues are labelled [`good first issue`](https://github.com/osintph/darkweb-scanner/labels/good%20first%20issue).

---

## License

MIT — see [LICENSE](LICENSE).
