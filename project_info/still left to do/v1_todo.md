# Scale VPN — v1 Productization & CLI Implementation Plan
> **Status:** Core Engine Complete | CLI & Packaging in Progress  
> **Target:** Preparing a polished, user-friendly CLI binary for friend testing & interview presentation.  
> **Last Updated:** August 2026

---

## 1. What Is Left to Build (CLI & Productization Layer)

Currently, the client runs as a raw binary script (`sudo ./scale-client`) that relies on a manual `.env` file. To turn this into a real CLI tool that friends can easily run from any directory, the following components are left:

```
scale (CLI Root)
├── scale login       # Interactive login; saves JWT to ~/.scale/token (0600)
├── scale up          # Starts VPN tunnel, background poller, and health monitor
├── scale status      # Pretty-prints client status, assigned IP, and relay state
├── scale peers       # Pretty-prints formatted table of mesh peers & ping status
├── scale down        # Stops active VPN session and removes wg0 interface
├── scale logout      # Clears local token and credentials
├── scale bugreport   # Generates safe, redacted diagnostic snapshot
└── scale version     # Displays build version, git commit, and architecture
```

---

## 2. Detailed Specifications for Remaining CLI Commands

### 2.1. `scale login`
* **Purpose:** Allows a user/friend to authenticate without manually creating `.env` files.
* **Behavior:**
  1. Prompts interactively for `Email` and `Password` (with password masked in terminal).
  2. Sends `POST /api/login` to `WG_CONTROL_SERVER`.
  3. On success, extracts JWT token and writes it to `~/.scale/token` with `0600` permissions.
  4. Outputs: `Login successful! Token saved to ~/.scale/token`.

---

### 2.2. `scale up`
* **Purpose:** Starts the userspace WireGuard engine and connects to the mesh.
* **Behavior:**
  1. Checks if running with root/`sudo` privileges (required for TUN device creation).
  2. Reads `~/.scale/token` (or prompts `Please run 'scale login' first`).
  3. Loads or generates `~/.scale/wg.key` (`0600`).
  4. Registers device with control plane, configures `wg0` (`100.64.x.x/16`), starts STUN Trickle ICE, and runs polling loop.
  5. Runs until `Ctrl+C` or `scale down` is called.

---

### 2.3. `scale status`
* **Purpose:** Quick glance at local VPN state.
* **Output Format:**
  ```text
  Scale VPN Client (v1.0.0)
  --------------------------------------------------
  Status:           CONNECTED (Tunnel active)
  Interface:        wg0
  Overlay IP:       100.64.0.2/16
  Public Key:       aBCdEFgH... (fingerprint)
  Control Server:   https://scale.yourdomain.com:8080 (OK)
  Relay Server:     wss://scale.yourdomain.com:8443 (Connected)
  NAT Type:         Easy / Port-Preserving
  Active Peers:     3 online
  ```

---

### 2.4. `scale peers`
* **Purpose:** Formatted terminal table showing all peers in the mesh.
* **Output Format:**
  ```text
  PEER IP        PUBLIC KEY    TRANSPORT       LAST PONG    STATUS
  100.64.0.1     x8K2mN9...    Direct UDP      2s ago       HEALTHY
  100.64.0.3     p4L9vB1...    WebSocket Relay 4s ago       HEALTHY (Relay)
  100.64.0.4     q1W8zC5...    Direct UDP      18s ago      DEGRADED
  ```

---

### 2.5. `scale down`
* **Purpose:** Cleanly stops the active VPN connection.
* **Behavior:**
  1. Sends stop signal to background workers and health monitor.
  2. Closes WireGuard device and deletes `wg0` interface.
  3. Restores standard kernel routing table.
  4. Outputs: `Scale VPN disconnected. Network interface wg0 removed.`

---

### 2.6. `scale logout`
* **Purpose:** Clears authenticated identity from local machine.
* **Behavior:**
  1. Deletes `~/.scale/token`.
  2. Deletes `~/.scale/wg.key` (or offers confirmation prompt).
  3. Outputs: `Logged out successfully. Local credentials cleared.`

---

### 2.7. `scale bugreport` (Safe Diagnostics)
* **Purpose:** Collects debug logs and network state for troubleshooting without leaking credentials.
* **Redaction Guarantees:**
  * Excludes `Authorization: Bearer <JWT>`.
  * Excludes WireGuard private keys (`wg.key`).
  * Excludes user passwords and raw environment secrets.
  * Captures only OS, kernel version, interface state, NAT classification, and peer count.

---

## 3. Installation & Distribution Scripts

### 3.1. `install.sh` (1-Click Linux Installer)
```bash
#!/usr/bin/env bash
set -e

echo "Installing Scale VPN..."

# 1. Build or download binary
go build -o scale ./cmd/scale-client

# 2. Move to system PATH
sudo mv scale /usr/local/bin/scale
sudo chmod +x /usr/local/bin/scale

# 3. Create secure state directory
mkdir -p "$HOME/.scale"
chmod 700 "$HOME/.scale"

echo "Scale installed successfully! Run 'scale login' to get started."
```

### 3.2. `uninstall.sh`
```bash
#!/usr/bin/env bash
set -e

echo "Uninstalling Scale VPN..."

# Stop any running interface
sudo ip link delete wg0 2>/dev/null || true

# Remove binary and state
sudo rm -f /usr/local/bin/scale
rm -rf "$HOME/.scale"

echo "Scale VPN uninstalled completely."
```

---

## 4. Ownership & Interview Strategy

| Feature Area | What You Own (Design & Contract) | What Is Delegated (Mechanics) |
|---|---|---|
| **CLI & Commands** | Command names, flags, lifecycle invariants (`up` owns context, `down` stops all workers). | Cobra boilerplate, argument parsing, ASCII table formatting. |
| **Credential Storage** | `~/.scale/` directory structure, `0700`/`0600` permissions, exclusion from git/logs. | `os.WriteFile` and `os.ReadFile` serialization. |
| **Diagnostics** | Strict allowlist/denylist: zero private keys, zero JWTs in bugreports. | JSON formatting and system info collection. |
| **Lifecycle & Concurrency** | Bounded context cancellation, `sync.WaitGroup` worker teardown, idempotent `up`/`down`. | Goroutine loop channel selects. |

### The Core Interview Talking Point:
> *"After engineering and verifying the WireGuard NAT traversal engine, STUN trickle resolution, and WebSocket relay failover mechanisms, I implemented a structured CLI with unified lifecycle controls. Every worker runs under a cancellable root context so that `scale down` cleanly destroys all kernel interfaces and sockets. To ensure security for real-world beta testers, credentials are stored in owner-restricted Unix state files (`0600`) and all diagnostic output is strictly sanitized to prevent credential leakage."*

---

## 5. Mandatory Infrastructure & Security Checklist (Non-Negotiable for Deployment)

Before distributing the v1 beta binary to friends or hosting on an EC2 instance / cloud server, the following infrastructure security requirements must be enforced:

| Requirement | Priority | Rationale & Fix Details |
|---|---|---|
| **PostgreSQL & Redis on `127.0.0.1`** | **100% Non-negotiable** | Automated bots on Shodan/Censys scan cloud IPs on port `5432` and `6379` within seconds of boot. Keeping them local (`localhost` only) prevents unauthorized database access, cache poisoning, and automated dictionary attacks. |
| **Restricted Firewall (`8080`, `8443`, `51820`)** | **100% Non-negotiable** | Only expose the API (`8080/tcp`), WebSocket Relay (`8443/tcp`), and WireGuard direct UDP (`51820/udp`). Ports `5432` (PostgreSQL) and `6379` (Redis) must remain strictly blocked from `0.0.0.0/0`. |
| **Secrets out of Git (`.gitignore`)** | **100% Essential** | Keeps your database password, `JWT_SECRET`, `DEVICE_AUTH_SECRET`, and `DERP_AUTH_KEY` private to your local deployment. Ensure `.env` is ignored and untrack any previously committed secrets/cookies (`git rm --cached`). |

