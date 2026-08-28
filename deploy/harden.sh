#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0"
  exit 1
fi

"$ROOT/bind_localhost.sh"
"$ROOT/setup_firewall.sh"
echo "Host hardened: localhost-only Postgres/Redis, restricted firewall."
