#!/bin/bash
set -e

echo "[BOOTSTRAP] Starting DNSProof VM bootstrap"

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
      apt update && apt install -y python3 python3-venv curl git unzip ufw dnsutils
      ;;
    yum)
      yum install -y python3 python3-venv curl git unzip firewalld
      ;;
    dnf)
      dnf install -y python3 python3-devel curl git unzip firewalld bind-utils
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
dnsproof.org {
    file /etc/coredns/zone/dnsproof.org.zone
    log
    errors
}
EOF

  # Create dnsproof zone file
  cat > /etc/coredns/zone/dnsproof.org.zone <<EOF
\$ORIGIN dnsproof.org.
@   3600 IN SOA ns1.dnsproof.org. admin.dnsproof.org. (
        2026010101 ; serial
        7200       ; refresh
        1800       ; retry
        1209600    ; expire
        3600 )     ; minimum
    IN NS ns1.dnsproof.org.
ns1 IN A 136.115.36.6
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
  pip install fastapi uvicorn[standard] aiofiles

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
ExecStart=/srv/dns/venv/bin/uvicorn agent:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  # Allow API port through UFW (optional if using GCP firewall)
  echo "[INFO] Allowing port 8000 through UFW..."
  sudo ufw allow 8000/tcp

  # Enable service
  systemctl daemon-reexec
  systemctl daemon-reload
  systemctl enable dnsagent.service
  systemctl start dnsagent.service

  echo "[INFO] dnsagent installed and running"
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

echo "[BOOTSTRAP] VM ready. CoreDNS running. You can now push updated Corefiles and zones."
