#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-}"
SSL_EMAIL="${SSL_EMAIL:-}"
CERT_DIR="/etc/nginx/certs"
mkdir -p "$CERT_DIR"

generate_self_signed() {
  echo "[nginx] Generating self-signed SSL certificate..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -subj "/C=US/ST=State/L=City/O=DarkWebScanner/CN=${DOMAIN:-localhost}" \
    -addext "subjectAltName=DNS:${DOMAIN:-localhost},IP:127.0.0.1" 2>/dev/null
  echo "[nginx] Self-signed certificate generated."
}

write_nginx_config() {
  local server_name="${DOMAIN:-_}"
  cat > /etc/nginx/conf.d/darkweb.conf <<EOF
server {
    listen 80;
    server_name ${server_name};

    # ACME challenge for Let's Encrypt renewal
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    # Redirect all HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name ${server_name};

    ssl_certificate     ${CERT_DIR}/cert.pem;
    ssl_certificate_key ${CERT_DIR}/key.pem;

    # Modern SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Proxy to Flask dashboard
    location / {
        proxy_pass http://dashboard:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }

    # WebSocket support (for future live log streaming)
    location /ws {
        proxy_pass http://dashboard:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
  echo "[nginx] Config written for server_name: ${server_name}"
}

# ── Main logic ────────────────────────────────────────────────────────────────
if [[ -n "$DOMAIN" && -n "$SSL_EMAIL" ]]; then
  echo "[nginx] Domain mode: $DOMAIN"

  # Check if we already have a valid Let's Encrypt cert
  LETSENCRYPT_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  if [[ -f "$LETSENCRYPT_CERT" ]]; then
    echo "[nginx] Existing Let's Encrypt cert found. Linking..."
    ln -sf "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_DIR/cert.pem"
    ln -sf "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERT_DIR/key.pem"
  else
    echo "[nginx] No cert found. Starting with self-signed for ACME challenge..."
    generate_self_signed
    write_nginx_config
    nginx &
    NGINX_PID=$!
    sleep 2

    echo "[nginx] Requesting Let's Encrypt certificate for $DOMAIN..."
    mkdir -p /var/www/certbot
    certbot certonly --webroot \
      --webroot-path /var/www/certbot \
      --email "$SSL_EMAIL" \
      --agree-tos \
      --no-eff-email \
      -d "$DOMAIN" || {
      echo "[nginx] Certbot failed — falling back to self-signed cert."
    }

    if [[ -f "$LETSENCRYPT_CERT" ]]; then
      echo "[nginx] Let's Encrypt cert obtained!"
      ln -sf "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_DIR/cert.pem"
      ln -sf "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CERT_DIR/key.pem"
    fi

    kill $NGINX_PID 2>/dev/null || true
    sleep 1
  fi

  write_nginx_config

  # Set up auto-renewal via cron
  echo "0 12 * * * certbot renew --quiet && nginx -s reload" | crontab -
  crond -b 2>/dev/null || true

else
  echo "[nginx] No DOMAIN set — using self-signed certificate."
  generate_self_signed
  write_nginx_config
fi

echo "[nginx] Starting Nginx..."
exec nginx -g "daemon off;"
