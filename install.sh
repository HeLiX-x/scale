#!/usr/bin/env bash
set -e

echo "Installing Scale VPN..."

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0")"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"

# 1. Build or download binary
go build -ldflags "-X main.Version=${VERSION} -X main.GitCommit=${COMMIT}" -o scale ./cmd/scale-client

# 2. Move to system PATH
sudo mv scale /usr/local/bin/scale
sudo chmod +x /usr/local/bin/scale

# 3. Create secure state directory
TARGET_HOME="${HOME}"
if [ -n "${SUDO_USER}" ]; then
  TARGET_HOME="$(eval echo "~${SUDO_USER}")"
fi
mkdir -p "${TARGET_HOME}/.scale"
chmod 700 "${TARGET_HOME}/.scale"
if [ -n "${SUDO_USER}" ]; then
  chown "${SUDO_USER}:${SUDO_USER}" "${TARGET_HOME}/.scale"
fi

echo "Scale installed successfully! Run 'scale login' to get started."
