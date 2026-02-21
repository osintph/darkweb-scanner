# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.4.0] - 2026-02-21

### Added
- **DNS Reconnaissance module** (`dns_crawler.py`) — passive + active DNS recon
  - Active DNS record queries (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA) via dnspython
  - Zone transfer (AXFR) attempts against all nameservers
  - Certificate transparency log enumeration via crt.sh (no API key required)
  - Subdomain enumeration via HackerTarget free API
  - Parallel subdomain resolution with IP geolocation (ip-api.com)
  - SPF, DMARC, and DKIM email security analysis with issue flagging
  - PTR / reverse DNS lookups on main A records
  - PDF report export with full structured results
- **DNS investigation history** — all recon results saved to database with full result JSON
- **DNS tab in dashboard** — full UI with history, live polling during recon, collapsible sections
- `DNSInvestigation` model added to storage layer
- `dnspython>=2.4` added to dependencies

## [0.3.0] - 2026-02-15

### Added
- **Curated daily threat intelligence digest** — separate from crawler report
  - CISA Known Exploited Vulnerabilities (KEV) with patch deadlines
  - AlienVault OTX threat pulses, SEA-prioritized
  - URLhaus recent malicious URLs (abuse.ch)
  - Feodo Tracker botnet C2 IPs filtered for SEA countries
  - Curated RSS feeds: Bleeping Computer, The Hacker News, Dark Reading, Krebs, Recorded Future, CISA
  - PDF generation with branded layout, clickable links throughout
  - HTML email body with clickable CVE links (NVD) and article links
- **External feed aggregator** (`feeds.py`)
  - `fetch_otx_pulses()` — subscribed + SEA-specific OTX search
  - `fetch_cisa_kev()` — CISA KEV catalog with configurable lookback
  - `fetch_urlhaus_recent()` — recent malicious URLs
  - `fetch_feodo_c2s()` — botnet C2 tracker with SEA geofencing
  - `fetch_rss_items()` — multi-source RSS/Atom parser
  - SEA relevance detection across all feed sources
- **Public subscribe endpoint** (`POST /api/digest/subscribe`) — honeypot bot protection, no auth required
- Digest subscriber management (add, remove, list)
- Daily digest scheduled at 08:00 PHT via cron
- On-demand digest send via dashboard

### Changed
- Digest PDF now a curated newsletter — crawler stats removed to separate Scanner Intelligence Report
- `build_digest_pdf()` signature: `(feed_data, scanner_summary, date)` — feeds separated from PDF build

## [0.2.0] - 2026-02-01

### Added
- **IP Investigation module** — parallel AbuseIPDB + VirusTotal lookups with history
- **Ransomware tracker** — 12+ active groups with SEA victim focus, live status
- **Threat actor profiles** — structured intelligence on APT and criminal groups targeting SEA
- **Telegram channel scraper** — monitors configurable public channels for threat intelligence
- **TOTP two-factor authentication** — QR code setup, per-user enrollment
- **OAuth login** — Google and GitHub SSO support
- **PDF report generation** — Scanner Intelligence Report via ReportLab
- Role-based access control (admin / analyst)
- Admin user management via dashboard UI

### Changed
- Dashboard authentication hardened — bcrypt passwords, session security

## [0.1.0] - 2024-01-01

### Added
- Async BFS crawler with configurable depth and concurrency
- Tor circuit rotation via stem
- Keyword scanner with category support and context windows
- SQLite and PostgreSQL storage backends via SQLAlchemy
- Webhook (Slack/Discord) and email alerting
- Flask dashboard with real-time hit viewer
- Docker Compose setup (Tor + app in one command)
- CLI with `scan`, `stats`, `hits`, `check-tor` commands
- GitHub Actions CI (lint, test, Docker build)
- Automated release workflow with GHCR publishing
