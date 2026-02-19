# Deployment Guide

## Production Setup on Ubuntu 22.04 VPS

### 1. Initial Server Hardening

```bash
# Update system
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
ufw allow 8080/tcp   # dashboard — consider restricting to your IP
ufw enable
```

### 2. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
usermod -aG docker scanner
```

### 3. Deploy the Application

```bash
su - scanner
git clone https://github.com/osintph/darkweb-scanner
cd darkweb-scanner
make setup

# Generate a hashed Tor control password
docker run --rm debian:bookworm-slim bash -c \
  "apt-get install -y tor -qq && tor --hash-password yourpassword 2>/dev/null | tail -1"
# Copy the output hash into docker/tor/torrc and set TOR_CONTROL_PASSWORD=yourpassword in .env

# Edit configuration
nano .env
nano config/keywords.yaml
nano config/seeds.txt

# Start everything
make run
```

### 4. Run Scans on a Schedule (systemd timer)

```bash
# Create a systemd service for scheduled scans
sudo tee /etc/systemd/system/darkweb-scan.service > /dev/null <<EOF
[Unit]
Description=Dark Web Scanner — crawl job
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
User=scanner
WorkingDirectory=/home/scanner/darkweb-scanner
ExecStart=/usr/bin/docker compose --profile scan run --rm scanner
EOF

sudo tee /etc/systemd/system/darkweb-scan.timer > /dev/null <<EOF
[Unit]
Description=Run Dark Web Scanner every 6 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now darkweb-scan.timer
```

### 5. Encrypted Storage (optional but recommended)

```bash
# Create an encrypted volume for scan data
apt install cryptsetup -y
dd if=/dev/urandom of=/data.img bs=1M count=10240   # 10GB
cryptsetup luksFormat /data.img
cryptsetup luksOpen /data.img scandata
mkfs.ext4 /dev/mapper/scandata
mkdir /mnt/scandata
mount /dev/mapper/scandata /mnt/scandata

# Update DATABASE_URL in .env to point to this volume
```

### 6. Dashboard Security

The dashboard has no authentication by default. In production, put it behind a reverse proxy with auth:

```bash
apt install nginx -y

# Basic auth
apt install apache2-utils -y
htpasswd -c /etc/nginx/.htpasswd osintph

# Nginx config
cat > /etc/nginx/sites-available/darkweb-scanner <<EOF
server {
    listen 443 ssl;
    server_name osintph.github.io;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://localhost:8080;
    }
}
EOF

ln -s /etc/nginx/sites-available/darkweb-scanner /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```
