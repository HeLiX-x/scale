#!/usr/bin/env bash
set -e

echo "Installing Scale VPN..."

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0")"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"

# 1. Locate Go binary
GO_BIN="$(command -v go || true)"
if [ -z "${GO_BIN}" ] && [ -x "/usr/local/go/bin/go" ]; then
  GO_BIN="/usr/local/go/bin/go"
fi
if [ -z "${GO_BIN}" ] && [ -n "${SUDO_USER}" ]; then
  USER_HOME="$(eval echo "~${SUDO_USER}")"
  for cand in "${USER_HOME}/go/bin/go" "${USER_HOME}/.local/go/bin/go" "/usr/local/go/bin/go" "/snap/bin/go"; do
    if [ -x "$cand" ]; then
      GO_BIN="$cand"
      break
    fi
  done
fi

if [ -z "${GO_BIN}" ]; then
  echo "Error: 'go' binary not found. Please install Go or ensure it is in your PATH."
  exit 1
fi

# Build binary
"${GO_BIN}" build -ldflags "-X main.Version=${VERSION} -X main.GitCommit=${COMMIT}" -o scale ./cmd/scale-client

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
