#!/usr/bin/env bash
set -e

echo "Uninstalling Scale VPN..."

# Stop any running interface
sudo ip link delete wg0 2>/dev/null || true

# Remove binary and state
sudo rm -f /usr/local/bin/scale

TARGET_HOME="${HOME}"
if [ -n "${SUDO_USER}" ]; then
  TARGET_HOME="$(eval echo "~${SUDO_USER}")"
fi
rm -rf "${TARGET_HOME}/.scale"

echo "Scale VPN uninstalled completely."
