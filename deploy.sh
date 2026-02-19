#!/usr/bin/env bash
# =============================================================================
#  darkweb-scanner — Zero-prerequisite deployment script
#  Repo: https://github.com/osintph/darkweb-scanner
#
#  Usage:
#    sudo bash deploy.sh
#
#  Optional env overrides:
#    INSTALL_DIR=/opt/darkweb-scanner sudo bash deploy.sh
#    DOMAIN=scanner.example.com SSL_EMAIL=you@example.com sudo bash deploy.sh
#    INSTALL_TIMER=1 sudo bash deploy.sh
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/osintph/darkweb-scanner"
INSTALL_DIR="${INSTALL_DIR:-$HOME/darkweb-scanner}"
DOMAIN="${DOMAIN:-}"
SSL_EMAIL="${SSL_EMAIL:-}"
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
[[ -f /etc/os-release ]] || error "Cannot detect OS — /etc/os-release missing."
source /etc/os-release
OS_ID="${ID,,}"
OS_LIKE="${ID_LIKE:-}"
info "Detected: $PRETTY_NAME"

is_debian_like() { [[ "$OS_ID" =~ ^(ubuntu|debian|kali|linuxmint|pop|raspbian)$ ]] || [[ "$OS_LIKE" =~ debian ]]; }
is_fedora_like() { [[ "$OS_ID" =~ ^(fedora)$ ]]; }
is_rhel_like()   { [[ "$OS_ID" =~ ^(rhel|centos|almalinux|rocky|ol)$ ]] || [[ "$OS_LIKE" =~ rhel ]]; }

# ── Install base packages ─────────────────────────────────────────────────────
info "Installing base packages..."
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

systemctl enable docker --now
success "Docker daemon running."

if [[ "$RUN_USER" != "root" ]]; then
  usermod -aG docker "$RUN_USER"
  success "User '$RUN_USER' added to docker group (log out/in to take effect)."
fi

docker compose version &>/dev/null || error "docker compose plugin not found."
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

# ── Copy example configs ──────────────────────────────────────────────────────
info "Copying example config files..."
cp -n .env.example .env                                  2>/dev/null || true
cp -n config/keywords.example.yaml config/keywords.yaml  2>/dev/null || true
cp -n config/seeds.example.txt config/seeds.txt          2>/dev/null || true
success "Config files ready."

# ── Patch .env ────────────────────────────────────────────────────────────────
SECRET_KEY="$(openssl rand -hex 32)"
sed -i "s/^DASHBOARD_SECRET_KEY=.*/DASHBOARD_SECRET_KEY=${SECRET_KEY}/" .env

# Set domain and SSL email if provided
if [[ -n "$DOMAIN" ]]; then
  sed -i "s/^DOMAIN=.*/DOMAIN=${DOMAIN}/" .env
  info "Domain set to: $DOMAIN"
fi
if [[ -n "$SSL_EMAIL" ]]; then
  sed -i "s/^SSL_EMAIL=.*/SSL_EMAIL=${SSL_EMAIL}/" .env
fi

success "Configuration patched."

# ── Generate Tor control password ─────────────────────────────────────────────
info "Building Tor image to generate control password hash..."
docker compose build tor

TOR_PLAIN_PASS="$(openssl rand -hex 16)"
TOR_HASH="$(docker run --rm darkweb-scanner-tor tor --hash-password "${TOR_PLAIN_PASS}" 2>/dev/null | grep '^16:' | tail -1)"

if [[ -n "$TOR_HASH" ]]; then
  sed -i "s|^# HashedControlPassword is injected.*|HashedControlPassword ${TOR_HASH}|" docker/tor/torrc
  grep -q "^HashedControlPassword" docker/tor/torrc || echo "HashedControlPassword ${TOR_HASH}" >> docker/tor/torrc
  sed -i "s/^TOR_CONTROL_PASSWORD=.*/TOR_CONTROL_PASSWORD=${TOR_PLAIN_PASS}/" .env
  success "Tor control password configured."
else
  warn "Could not generate Tor hash — circuit rotation may not work."
  sed -i '/^# HashedControlPassword is injected/d' docker/tor/torrc
fi

# ── Build all images ──────────────────────────────────────────────────────────
info "Building all Docker images (this may take a few minutes)..."
docker compose build --no-cache
success "Images built."

# ── Start all services ────────────────────────────────────────────────────────
info "Starting all containers..."
docker compose up -d
success "Containers started."

# ── Wait for dashboard ────────────────────────────────────────────────────────
info "Waiting for services to be ready..."
TIMEOUT=90; ELAPSED=0
until curl -sfk "https://localhost" -o /dev/null 2>/dev/null; do
  [[ $ELAPSED -ge $TIMEOUT ]] && { warn "HTTPS not responding after ${TIMEOUT}s. Check: docker compose logs nginx"; break; }
  sleep 3; ELAPSED=$((ELAPSED + 3))
done
curl -sfk "https://localhost" -o /dev/null 2>/dev/null && success "HTTPS is live!"

# ── Wait for Tor to bootstrap ─────────────────────────────────────────────────
info "Waiting for Tor to bootstrap (up to 3 minutes)..."
ELAPSED=0
until docker compose logs tor 2>/dev/null | grep -q "Bootstrapped 100%"; do
  if [[ $ELAPSED -ge 180 ]]; then
    warn "Tor still bootstrapping — check with: docker compose logs tor | grep Bootstrapped"
    break
  fi
  sleep 10; ELAPSED=$((ELAPSED + 10))
done
docker compose logs tor 2>/dev/null | grep -q "Bootstrapped 100%" && success "Tor bootstrapped and ready."

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
if [[ -n "$DOMAIN" ]]; then
  echo -e "  🌐 Dashboard:    ${CYAN}https://${DOMAIN}${NC}"
else
  echo -e "  🌐 Dashboard:    ${CYAN}https://YOUR_SERVER_IP${NC}  (self-signed cert — accept browser warning)"
  echo -e "  💡 For a real SSL cert, redeploy with:"
  echo -e "     ${YELLOW}DOMAIN=yourdomain.com SSL_EMAIL=you@email.com sudo bash deploy.sh${NC}"
fi
echo ""
echo -e "${YELLOW}Edit your configuration before running scans:${NC}"
echo -e "  nano ${INSTALL_DIR}/.env"
echo -e "  nano ${INSTALL_DIR}/config/keywords.yaml"
echo -e "  nano ${INSTALL_DIR}/config/seeds.txt"
echo ""
echo -e "${YELLOW}Useful commands (run from ${INSTALL_DIR}):${NC}"
echo -e "  make scan          # run a crawl (foreground)"
echo -e "  make check-tor     # verify Tor connectivity"
echo -e "  make stats         # show scan statistics"
echo -e "  make hits          # show keyword hits"
echo -e "  make logs          # tail all container logs"
echo -e "  make stop          # stop all containers"
echo ""
if [[ "$RUN_USER" != "root" ]]; then
  echo -e "${YELLOW}⚠️  Log out and back in${NC} (or run 'newgrp docker') so"
  echo -e "   '${RUN_USER}' can use docker without sudo."
  echo ""
fi
