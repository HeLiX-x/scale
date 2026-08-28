#!/usr/bin/env bash
set -euo pipefail

echo "Applying Scale VPN host firewall..."

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0"
  exit 1
fi

if ! command -v ufw >/dev/null 2>&1; then
  apt-get update
  apt-get install -y ufw
fi

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow 22/tcp comment 'SSH'
ufw allow 8080/tcp comment 'Scale control plane'
ufw allow 8443/tcp comment 'Scale WebSocket relay'
ufw allow 51820/udp comment 'WireGuard P2P'

ufw deny 5432/tcp comment 'PostgreSQL localhost only'
ufw deny 6379/tcp comment 'Redis localhost only'

ufw --force enable
ufw status verbose

echo "Firewall active. Public: 22/tcp, 8080/tcp, 8443/tcp, 51820/udp. Blocked: 5432, 6379."
