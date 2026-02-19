#!/usr/bin/env bash
# =============================================================================
#  darkweb-scanner — Zero-prerequisite deployment script
#  Repo: https://github.com/osintph/darkweb-scanner
#  Assumes nothing installed — installs Docker, clones repo, configures & runs.
#
#  Usage:
#    sudo bash deploy.sh
#
#  Optional env overrides:
#    INSTALL_DIR=/opt/darkweb-scanner sudo bash deploy.sh
#    DASHBOARD_PORT=9090 sudo bash deploy.sh
#    INSTALL_TIMER=1 sudo bash deploy.sh    # enable 6-hour systemd scan timer
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/osintph/darkweb-scanner"
INSTALL_DIR="${INSTALL_DIR:-$HOME/darkweb-scanner}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8080}"
RUN_USER="${SUDO_USER:-$(whoami)}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Please run as root:  sudo bash deploy.sh"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     darkweb-scanner  —  Deployment       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── Detect OS ────────────────────────────────────────────────────────────────
info "Detecting OS..."
[[ -f /etc/os-release ]] || error "Cannot detect OS — /etc/os-release missing."
source /etc/os-release
OS_ID="${ID,,}"
OS_LIKE="${ID_LIKE:-}"
info "Detected: $PRETTY_NAME"

is_debian_like() { [[ "$OS_ID" =~ ^(ubuntu|debian|kali|linuxmint|pop|raspbian)$ ]] || [[ "$OS_LIKE" =~ debian ]]; }
is_fedora_like() { [[ "$OS_ID" =~ ^(fedora)$ ]]; }
is_rhel_like()   { [[ "$OS_ID" =~ ^(rhel|centos|almalinux|rocky|ol)$ ]] || [[ "$OS_LIKE" =~ rhel ]]; }

# ── Install base packages ─────────────────────────────────────────────────────
info "Installing base packages (curl, git, make, gnupg)..."
if is_debian_like; then
  apt-get update -qq
  apt-get install -y --no-install-recommends curl git make ca-certificates gnupg lsb-release openssl
elif is_fedora_like; then
  dnf install -y curl git make ca-certificates gnupg openssl
elif is_rhel_like; then
  dnf install -y curl git make ca-certificates gnupg openssl
else
  error "Unsupported distro: $OS_ID"
fi
success "Base packages ready."

# ── Install Docker CE ─────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  info "Installing Docker CE..."
  if is_debian_like; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/${OS_ID} $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif is_fedora_like; then
    dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif is_rhel_like; then
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
  success "Docker installed."
else
  success "Docker already installed: $(docker --version)"
fi

# ── Start Docker daemon ───────────────────────────────────────────────────────
info "Enabling Docker daemon..."
systemctl enable docker --now
success "Docker daemon running."

# ── Add user to docker group ──────────────────────────────────────────────────
if [[ "$RUN_USER" != "root" ]]; then
  usermod -aG docker "$RUN_USER"
  success "User '$RUN_USER' added to docker group (log out/in to take effect)."
fi

# ── Verify docker compose plugin ─────────────────────────────────────────────
docker compose version &>/dev/null || error "docker compose plugin not found. Please install docker-compose-plugin."
success "docker compose: $(docker compose version --short)"

# ── Clone or update repo ──────────────────────────────────────────────────────
info "Setting up repo at $INSTALL_DIR..."
if [[ -d "$INSTALL_DIR/.git" ]]; then
  warn "Repo exists — pulling latest..."
  git -C "$INSTALL_DIR" pull --ff-only || warn "Pull failed (local changes?). Continuing."
else
  git clone "$REPO_URL" "$INSTALL_DIR"
fi
[[ "$RUN_USER" != "root" ]] && chown -R "$RUN_USER":"$RUN_USER" "$INSTALL_DIR"
success "Repo ready at $INSTALL_DIR"

cd "$INSTALL_DIR"

# ── Copy example configs (make setup equivalent) ──────────────────────────────
info "Copying example config files..."
cp -n .env.example .env                                  2>/dev/null || true
cp -n config/keywords.example.yaml config/keywords.yaml  2>/dev/null || true
cp -n config/seeds.example.txt config/seeds.txt          2>/dev/null || true
success "Config files ready."

# ── Patch .env defaults ───────────────────────────────────────────────────────
sed -i "s/^DASHBOARD_PORT=.*/DASHBOARD_PORT=${DASHBOARD_PORT}/" .env

# Generate a strong dashboard secret key
SECRET_KEY="$(openssl rand -hex 32)"
sed -i "s/^DASHBOARD_SECRET_KEY=.*/DASHBOARD_SECRET_KEY=${SECRET_KEY}/" .env
success "Dashboard secret key generated."

# ── Generate Tor control password hash ───────────────────────────────────────
info "Generating Tor control password (using Docker)..."
TOR_PLAIN_PASS="$(openssl rand -hex 16)"
TOR_HASH="$(docker run --rm debian:bookworm-slim bash -c \
  "apt-get install -y tor -qq 2>/dev/null && tor --hash-password '${TOR_PLAIN_PASS}' 2>/dev/null | tail -1")" || TOR_HASH=""

if [[ -n "$TOR_HASH" ]]; then
  sed -i "s/^TOR_CONTROL_PASSWORD=.*/TOR_CONTROL_PASSWORD=${TOR_PLAIN_PASS}/" .env
  TORRC="docker/tor/torrc"
  if grep -q "HashedControlPassword" "$TORRC" 2>/dev/null; then
    sed -i "s|^HashedControlPassword .*|HashedControlPassword ${TOR_HASH}|" "$TORRC"
  else
    echo "HashedControlPassword ${TOR_HASH}" >> "$TORRC"
  fi
  success "Tor control password configured."
else
  warn "Could not auto-generate Tor hash. Update TOR_CONTROL_PASSWORD in .env and HashedControlPassword in docker/tor/torrc manually."
fi

# ── Build Docker images ───────────────────────────────────────────────────────
info "Building Docker images (first run may take a few minutes)..."
docker compose build --no-cache
success "Images built."

# ── Start Tor + Dashboard ─────────────────────────────────────────────────────
info "Starting containers (Tor + Dashboard)..."
# Note: 'scanner' service uses the 'scan' profile and is NOT started here.
# Start it manually with:  make scan   OR   docker compose --profile scan run --rm scanner
docker compose up -d
success "Containers started."

# ── Wait for dashboard ────────────────────────────────────────────────────────
info "Waiting for dashboard on http://localhost:${DASHBOARD_PORT} ..."
TIMEOUT=90; ELAPSED=0
until curl -sf "http://localhost:${DASHBOARD_PORT}" -o /dev/null 2>/dev/null; do
  [[ $ELAPSED -ge $TIMEOUT ]] && { warn "Dashboard not responding after ${TIMEOUT}s. Run: docker compose logs"; break; }
  sleep 3; ELAPSED=$((ELAPSED + 3))
done
curl -sf "http://localhost:${DASHBOARD_PORT}" -o /dev/null 2>/dev/null && success "Dashboard is live!"

# ── Wait for Tor healthcheck ──────────────────────────────────────────────────
info "Waiting for Tor healthcheck (up to 60s)..."
ELAPSED=0
until docker compose ps tor 2>/dev/null | grep -q "healthy"; do
  [[ $ELAPSED -ge 60 ]] && { warn "Tor not healthy yet — check with: make check-tor"; break; }
  sleep 5; ELAPSED=$((ELAPSED + 5))
done
docker compose ps tor 2>/dev/null | grep -q "healthy" && success "Tor is healthy."

# ── Optional: systemd scan timer ─────────────────────────────────────────────
if [[ "${INSTALL_TIMER:-}" == "1" ]]; then
  info "Installing systemd scan timer (every 6 hours)..."
  tee /etc/systemd/system/darkweb-scan.service > /dev/null <<EOF
[Unit]
Description=Dark Web Scanner — scheduled crawl
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/docker compose --profile scan run --rm scanner
EOF

  tee /etc/systemd/system/darkweb-scan.timer > /dev/null <<EOF
[Unit]
Description=Run Dark Web Scanner every 6 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now darkweb-scan.timer
  success "Systemd scan timer enabled (every 6h)."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              ✅  Deployment Complete                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  📁 Install dir:  ${CYAN}${INSTALL_DIR}${NC}"
echo -e "  🌐 Dashboard:    ${CYAN}http://localhost:${DASHBOARD_PORT}${NC}"
echo ""
echo -e "${YELLOW}Edit your configuration before running scans:${NC}"
echo -e "  nano ${INSTALL_DIR}/.env                     # DB, alerting, Tor settings"
echo -e "  nano ${INSTALL_DIR}/config/keywords.yaml     # keywords to watch for"
echo -e "  nano ${INSTALL_DIR}/config/seeds.txt         # .onion seed URLs"
echo ""
echo -e "${YELLOW}Useful commands (run from ${INSTALL_DIR}):${NC}"
echo -e "  make scan          # run a crawl (foreground, uses 'scan' profile)"
echo -e "  make check-tor     # verify Tor connectivity"
echo -e "  make stats         # show scan statistics"
echo -e "  make hits          # show keyword matches"
echo -e "  make logs          # tail all container logs"
echo -e "  make stop          # stop all containers"
echo -e "  make shell         # open shell inside app container"
echo ""
if [[ "$RUN_USER" != "root" ]]; then
  echo -e "${YELLOW}⚠️  Log out and back in${NC} (or run 'newgrp docker') so"
  echo -e "   '${RUN_USER}' can use docker without sudo."
  echo ""
fi
