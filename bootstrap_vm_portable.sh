#!/bin/bash
set -e

AGENT_SECRET="$1"
NAMESERVER_IP="$2"
DOMAIN="$3"
NS_NAME="$4"

if [ -z "$AGENT_SECRET" ] || [ -z "$NAMESERVER_IP" ] || [ -z "$DOMAIN" ] || [ -z "$NS_NAME" ]; then
  echo "Usage: $0 AGENT_SECRET IP DOMAIN NS_NAME"
  echo "Example: $0 supersecretkey 1.2.3.4 dnsproof.org ns1.dnsproof.org"
  exit 1
fi

ENV_FILE="/srv/dns/.env"

echo "[BOOTSTRAP] Starting DNSProof VM bootstrap"

# Create .env directory if not exists
sudo mkdir -p /srv/dns

# Save AGENT_SECRET to .env
echo "AGENT_SECRET=$AGENT_SECRET" | sudo tee "$ENV_FILE" > /dev/null

# Optional: Secure the .env file
sudo chmod 600 "$ENV_FILE"
sudo chown root:root "$ENV_FILE"

echo ".env file created at $ENV_FILE"

#----------------------------
# OS + Package Manager Setup
#----------------------------
detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
  else
    echo "[ERROR] Cannot detect OS. Exiting."
    exit 1
  fi

  case "$OS" in
    ubuntu|debian)
      PKG_MANAGER="apt"
      ;;
    centos|rocky|rhel)
      PKG_MANAGER="dnf"
      ;;
    amzn)
      PKG_MANAGER="yum"
      ;;
    *)
      echo "[ERROR] Unsupported OS: $OS"
      exit 1
      ;;
  esac

  echo "[INFO] Detected OS: $OS ($VERSION), Package Manager: $PKG_MANAGER"
}

#----------------------------
# Install Core Dependencies
#----------------------------
install_packages() {
  echo "[INFO] Installing dependencies..."

  case "$PKG_MANAGER" in
    apt)
      apt update && apt install -y \
        python3 python3-venv curl git unzip \
        ufw dnsutils ldnsutils
      ;;

    dnf)
      dnf install -y \
        python3 python3-devel curl git unzip \
        firewalld bind-utils epel-release
      dnf install -y ldns
      ;;
  esac
}

#----------------------------
# Clean Up Old Stuff
#----------------------------
clean_old_install() {
  echo "[INFO] Cleaning up old services..."

  systemctl stop dnsagent 2>/dev/null || true
  systemctl disable dnsagent 2>/dev/null || true
  rm -f /etc/systemd/system/dnsagent.service

  systemctl stop coredns 2>/dev/null || true
  systemctl disable coredns 2>/dev/null || true
  rm -f /etc/systemd/system/coredns.service

  systemctl daemon-reload

  rm -rf /srv/dns/venv
  rm -rf /root/.acme.sh
  rm -rf /home/*/.acme.sh

  echo "[INFO] Old installs cleaned."
}

#----------------------------
# Configure Firewall
#----------------------------
configure_firewall() {
  echo "[INFO] Configuring firewall..."

  if command -v ufw >/dev/null 2>&1; then
    ufw allow 53
    ufw allow 53/udp
    ufw allow ssh
    ufw --force enable
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=53/tcp
    firewall-cmd --permanent --add-port=53/udp
    firewall-cmd --reload
  else
    echo "[WARN] No firewall found or managed"
  fi
}

#----------------------------
# Disable systemd-resolved and fix /etc/hosts
#----------------------------
fix_port53_conflict_and_hostname() {
  echo "[INFO] Disabling systemd-resolved (port 53 blocker)..."

  systemctl disable systemd-resolved || true
  systemctl stop systemd-resolved || true

  echo "nameserver 8.8.8.8" > /etc/resolv.conf

  # Fix hostname resolution
  HOSTNAME_FULL=$(hostname)
  echo "127.0.0.1 $HOSTNAME_FULL" >> /etc/hosts
  echo "[INFO] Added $HOSTNAME_FULL to /etc/hosts"
}

#----------------------------
# Install and Configure CoreDNS
#----------------------------
install_coredns() {
  echo "[INFO] Installing CoreDNS..."

  mkdir -p /opt/coredns
  cd /opt/coredns

  COREDNS_VERSION="1.11.1"
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) echo "[ERROR] Unsupported architecture: $ARCH"; exit 1 ;;
  esac

  curl -LO "https://github.com/coredns/coredns/releases/download/v${COREDNS_VERSION}/coredns_${COREDNS_VERSION}_linux_${ARCH}.tgz"
  tar -xzf coredns_${COREDNS_VERSION}_linux_${ARCH}.tgz
  mv coredns /usr/local/bin/coredns
  chmod +x /usr/local/bin/coredns

  # Create default Corefile
  mkdir -p /etc/coredns/zone
  cat > /etc/coredns/Corefile <<EOF
$DOMAIN {
    file /etc/coredns/zone/$DOMAIN.zone
    log
    errors
}
EOF

  # Create dnsproof zone file
  cat > /etc/coredns/zone/dnsproof.org.zone <<EOF
\$ORIGIN dnsproof.org.
@   3600 IN SOA $NS_NAME. admin.$DOMAIN. (
        2026010101 ; serial
        7200       ; refresh
        1800       ; retry
        1209600    ; expire
        3600 )     ; minimum
    IN NS ns1.dnsproof.org.
ns1 IN A $NAMESERVER_IP
@ IN TXT "test"
EOF

  # Systemd service
  cat > /etc/systemd/system/coredns.service <<EOF
[Unit]
Description=CoreDNS DNS server
After=network.target

[Service]
ExecStart=/usr/local/bin/coredns -conf /etc/coredns/Corefile
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable coredns
  systemctl start coredns

  echo "[INFO] CoreDNS installed and running"
}

setup_dnsaget() {
  echo "[INFO] Setting up dnsagent..."

  # Create venv in /srv/dns
  mkdir -p /srv/dns
  cd /srv/dns
  python3 -m venv venv
  . venv/bin/activate

  # Upgrade pip and install requirements
  pip install --upgrade pip
  pip install fastapi uvicorn[standard] aiofiles dnspython requests

  # Optional: drop your actual source files here
  echo "# Placeholder agent.py" > /srv/dns/agent.py

  # Create systemd unit
  cat > /etc/systemd/system/dnsagent.service <<EOF
[Unit]
Description=DNS Agent API (VM-side)
After=network.target

[Service]
User=root
WorkingDirectory=/srv/dns
ExecStart=/srv/dns/venv/bin/python3 -m uvicorn agent:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  # Allow API port (8000) through firewall
  echo "[INFO] Allowing port 8000 through firewall..."

  if command -v ufw >/dev/null 2>&1; then
    ufw allow 8000/tcp
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=8000/tcp
    firewall-cmd --reload
  else
    echo "[WARN] No firewall tool (ufw or firewalld) found. Skipping port 8000 rule."
  fi

  # Enable service
  systemctl daemon-reexec
  systemctl daemon-reload
  systemctl enable dnsagent.service
  systemctl start dnsagent.service

  echo "[INFO] dnsagent installed and running"
}

setup_DNSSEC_cron() {
  echo "[INFO] Setting up daily DNSSEC re-signing cron job..."
  
  CRON_JOB="0 3 * * * /srv/dns/venv/bin/python /srv/dns/dnssec_resign_cron.py >> /var/log/dnssec_resign.log 2>&1"
  CRONTAB_TMP=$(mktemp)

  echo "[DEBUG] Ensuring log file exists..."
  touch /var/log/dnssec_resign.log || { echo "[ERROR] Could not create log file"; return 1; }
  chown root:root /var/log/dnssec_resign.log || { echo "[ERROR] Could not chown log file"; return 1; }

  echo "[DEBUG] Reading current crontab into temp file: $CRONTAB_TMP"
  crontab -l 2>/dev/null > "$CRONTAB_TMP" || true

  echo "[DEBUG] Checking if cron job already exists..."
  if grep -Fq "$CRON_JOB" "$CRONTAB_TMP"; then
    echo "[INFO] Cron job already present. Skipping."
  else
    echo "[DEBUG] Appending new cron job:"
    echo "$CRON_JOB"
    echo "$CRON_JOB" >> "$CRONTAB_TMP"

    echo "[DEBUG] Installing updated crontab..."
    crontab "$CRONTAB_TMP" && echo "[INFO] Cron job installed." || echo "[ERROR] Failed to install crontab"
  fi

  rm "$CRONTAB_TMP"

  # Ensure auto-resign config is initialized
  mkdir -p /etc/dnsproof
  echo "true" > /etc/dnsproof/auto_resign_enabled
}

#----------------------------
# MAIN
#----------------------------
detect_os
install_packages
clean_old_install
configure_firewall
fix_port53_conflict_and_hostname
install_coredns
setup_dnsaget
setup_DNSSEC_cron

echo "[BOOTSTRAP] VM ready. CoreDNS running. You can now push updated Corefiles and zones."
