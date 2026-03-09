# Changelog

All notable changes to this project will be documented in this file.
The format follows **Keep a Changelog**. This project adheres to **Semantic Versioning**.

## [Unreleased]

## [1.0.0] - 2026-03-09

### Added
- **Active subdomain brute-force** (`dns_crawler.py`)
  - 100-entry built-in wordlist covering common prefixes: `www`, `api`, `mail`, `vpn`, `dev`, `staging`, `admin`, `portal`, `git`, `ci`, `monitor`, `db`, and more
  - Runs in parallel (50 workers) via `ThreadPoolExecutor` — a 100-entry scan typically completes in under 5 seconds
  - Brute-forced subdomains are merged with passive results and deduplicated before resolution
  - Runs automatically as Phase 2b of every `run_dns_recon()` call — no config needed
  - Results tagged with `source: bruteforce` to distinguish them from passive discovery
- **TCP port scanner** (`dns_crawler.py`)
  - `scan_ports()` — scans a single host across a configurable port list using non-blocking TCP connect
  - `scan_ports_multi()` — fans out to all resolved IPs in parallel (capped at 10 hosts)
  - 30 common ports covered: FTP, SSH, Telnet, SMTP, DNS, HTTP, HTTPS, SMB, MySQL, MSSQL, PostgreSQL, Redis, MongoDB, RDP, VNC, Elasticsearch, Kubernetes API, Prometheus, and more
  - Per-port timeout configurable (`PORT_SCAN_TIMEOUT`, default 1.5s); full scan of 30 ports against one host takes ~2–3 seconds
  - Returns `open`, `closed`, or `filtered` per port
- **HTTP/HTTPS directory enumeration** (`dns_crawler.py`)
  - `enumerate_directories()` — probes a target host for 70 common paths using real HTTP GET requests
  - Auto-detects HTTPS vs HTTP availability before scanning
  - Skips 404 and 410 responses; surfaces all other status codes (200, 301, 302, 401, 403, 500, etc.)
  - Returns path, full URL, status code, content-length, and redirect destination per result
  - Runs against the root domain and first two resolved IPs
  - `run_port_and_dir_scan()` — orchestrates port scan + dir enum for all IPs from a DNS investigation
- **Two new API endpoints** (`dashboard_routes.py`)
  - `POST /api/dns/investigations/<id>/scan` — triggers port scan + directory enumeration in a background thread; merges results back into the investigation's stored JSON
  - `GET /api/dns/investigations/<id>/scan/status` — poll for scan completion; returns `ready` flag plus full `port_scan` and `dir_enum` data when done
- **Redesigned DNS tab UI** (`index.html`)
  - Six view tabs: **Graph**, **Subdomains**, **Ports**, **Directories**, **Email Security**, **DNS Records**
  - **Graph view** — interactive SVG canvas node graph; root domain at center, subdomains in concentric rings by depth, IP nodes branching off; drag nodes, pan, scroll-to-zoom; brute-forced nodes shown in purple, passive in blue
  - **Subdomains view** — unified table merging passive, brute-forced, and crt.sh results with per-row source badges; zone transfer records shown inline if a transfer succeeded
  - **Ports view** — per-IP port heatmap grid (green = open, yellow = filtered, grey = closed/unknown); scan triggered on demand via "🔌 Scan Ports & Dirs" button with live polling
  - **Directories view** — table of all non-404 HTTP responses with status code color-coding (green = 200, blue = redirects, yellow = 401/403, red = 500); empty state prompts user to trigger scan
  - **Email Security view** — 0–100 score card calculated from SPF/DMARC/DKIM presence and policy strength; per-record pass/warn/fail cards; full TXT record dump
  - **DNS Records view** — all record types in a clean table with inline PTR lookups and geolocation
  - Stat strip at top of result showing subdomain count, resolved count, brute-forced count, crt.sh cert count, IP count, zone transfer status, SPF, and DMARC at a glance
  - Progress indicator during recon shows which phase is running (DNS → crt.sh → HackerTarget → brute-force → zone transfer → geolocation)

### Changed
- `dns_crawler.py` — `run_dns_recon()` now includes Phase 2b (active brute-force) automatically; `subdomains_bruteforce` key added to result dict
- `dashboard_routes.py` — two new scan endpoints added before the Projects API section
- `index.html` — DNS tab panel HTML, CSS, and all JavaScript replaced with new multi-view implementation; old `renderDNSResult` / `dnsSection` / `toggleDNSSection` functions replaced by modular view builders



### Added
- **Channel Monitor tab** — on-demand Telegram channel scraping directly from the dashboard UI
  - Enter any public channel username, invite link, or @handle and run a scan without CLI access
  - Configurable options: message limit, date range (last N days), forced source language, max video size, min free disk threshold, skip-English toggle
  - Auto-detects message language per-message using `langdetect`
  - Auto-translates all non-English messages to English using `deep-translator` (Google Translate)
  - Downloads photos and videos inline; videos skipped if they exceed the configured size limit
  - Live streaming log — output appears in the dashboard console panel in real time (1.5s polling)
  - Results packaged as a downloadable ZIP: `messages.html` (full rendered report with inline media), `messages.json` (raw data), and `media/` folder
  - Job history table with view-log, re-download, and delete actions for the current server session
  - Credential check on tab load — shows warning banner if `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, or `TELEGRAM_PHONE` are not set
- `channel_monitor.py` — standalone channel scraping module (also usable from CLI)
- `channel_monitor_routes.py` — new Flask blueprint for all Channel Monitor API endpoints
- `TELEGRAM_PHONE` environment variable — required for Channel Monitor interactive auth
- `deep-translator>=1.11` and `langdetect>=1.0` added to dashboard dependencies

### Changed
- `app.py` — registers the new `channel_monitor_bp` blueprint
- `index.html` — adds **📡 Channel Monitor** nav tab, panel UI, and all supporting JS
- `pyproject.toml` — adds `deep-translator` and `langdetect` to `[project.optional-dependencies.dashboard]`
- `.env.example` — documents `TELEGRAM_PHONE`

## [0.6.0] - 2026-02-23

### Added
- **PostgreSQL migration** — platform now runs on PostgreSQL 16 (was SQLite)
  - `postgres:16-alpine` service added to Docker Compose
  - All 15 tables migrated: 44,344 crawled pages, 3,802 keyword hits, 4 users, 280 project hits
  - Migration script handles SQLite boolean → PostgreSQL boolean casting automatically
  - `pg_data` named volume for persistent storage
  - `POSTGRES_PASSWORD` added to environment configuration

## [0.5.0] - 2026-02-22

### Added
- **Web Check integration** — on-demand OSINT analysis for any domain
  - Runs as a separate Docker service (`webcheck`) at `webcheck.osintph.info`
  - Full Let's Encrypt SSL on the subdomain
  - Reskinned to match dashboard color scheme (GitHub dark palette)
  - Accessible via **🔍 Web Check** button in dashboard nav bar (opens in new tab)
  - Provides: DNS, SSL, open ports, tech stack, WHOIS, headers, SPF/DKIM/DMARC, screenshots, and more
- **Projects feature** — scoped monitoring engagements
  - Per-project keywords, target domains, entities, and hit tracking
  - Project cards with color coding and status (active/paused/archived)
  - Full CRUD UI with Overview, Keywords, Domains, Entities, and Hits sub-tabs
  - Hit matching engine links incoming crawl/Telegram hits to relevant projects automatically
- **Paste Monitor** — monitors rentry.co for keyword hits
  - Scans paste sites for credential leaks, data dumps, and threat intel
  - Integrated into main keyword hit pipeline
- **Telegram scraper enhancements**
  - Expanded to 49 channels covering SEA/PH threat intel, ransomware, leaks, and CVEs
  - Dead channel auto-detection and removal
- **PH Indicators project** — 25 Philippine-specific keywords pre-loaded
  - Mobile/telecom prefixes, major banks, government agencies, and general PH terms
- **Static site** (`www.osintph.info`) — multilingual landing page (EN, DE, TH)
  - Separate private git repo: `osintph/osintph-www`, added as submodule

### Changed
- Nginx `X-Frame-Options` updated to `SAMEORIGIN` on www vhost

## [0.4.0] - 2026-02-21

### Added
- DNS Reconnaissance module (`dns_crawler.py`) — passive + active DNS recon
  - Active DNS record queries (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA) via dnspython
  - Zone transfer (AXFR) attempts against all nameservers
  - Certificate transparency log enumeration via crt.sh (no API key required)
  - Subdomain enumeration via HackerTarget free API
  - Parallel subdomain resolution with IP geolocation (ip-api.com)
  - SPF, DMARC, and DKIM email security analysis with issue flagging
  - PTR / reverse DNS lookups on main A records
  - PDF report export with full structured results
- DNS investigation history — all recon results saved to database with full result JSON
- DNS tab in dashboard — full UI with history, live polling during recon, collapsible sections
- `DNSInvestigation` model added to storage layer
- `dnspython>=2.4` added to dependencies

## [0.3.0] - 2026-02-15

### Added
- Curated daily threat intelligence digest — separate from crawler report
  - CISA Known Exploited Vulnerabilities (KEV) with patch deadlines
  - AlienVault OTX threat pulses, SEA-prioritized
  - URLhaus recent malicious URLs (abuse.ch)
  - Feodo Tracker botnet C2 IPs filtered for SEA countries
  - Curated RSS feeds: Bleeping Computer, The Hacker News, Dark Reading, Krebs, Recorded Future, CISA
  - PDF generation with branded layout, clickable links throughout
  - HTML email body with clickable CVE links (NVD) and article links
- External feed aggregator (`feeds.py`)
  - `fetch_otx_pulses()` — subscribed + SEA-specific OTX search
  - `fetch_cisa_kev()` — CISA KEV catalog with configurable lookback
  - `fetch_urlhaus_recent()` — recent malicious URLs
  - `fetch_feodo_c2s()` — botnet C2 tracker with SEA geofencing
  - `fetch_rss_items()` — multi-source RSS/Atom parser
  - SEA relevance detection across all feed sources
- Public subscribe endpoint (`POST /api/digest/subscribe`) — honeypot bot protection, no auth required
- Digest subscriber management (add, remove, list)
- Daily digest scheduled at 08:00 PHT via cron
- On-demand digest send via dashboard

### Changed
- Digest PDF now a curated newsletter — crawler stats removed to separate Scanner Intelligence Report
- `build_digest_pdf()` signature: `(feed_data, scanner_summary, date)` — feeds separated from PDF build

## [0.2.0] - 2026-02-01

### Added
- IP Investigation module — parallel AbuseIPDB + VirusTotal lookups with history
- Ransomware tracker — 12+ active groups with SEA victim focus, live status
- Threat actor profiles — structured intelligence on APT and criminal groups targeting SEA
- Telegram channel scraper — monitors configurable public channels for threat intelligence
- TOTP two-factor authentication — QR code setup, per-user enrollment
- OAuth login — Google and GitHub SSO support
- PDF report generation — Scanner Intelligence Report via ReportLab
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

## [v0.9.1] - 2026-03-07
### Fixed
- genProjectSelect dropdown not populating with projects on Keywords tab load
- API returns plain array but code was reading `pd.projects` — fixed to `Array.isArray(pd)`
- `.panel` CSS `overflow:hidden` was clipping the dropdown — changed to `visible`
- Flask template cache required `docker compose restart` to pick up changes

### Changed
- `_populateGenProjectDropdown()` extracted as standalone function, called on tab switch
