# Scale VPN — v1 Deployment & Real-World Testing Guide
> **Target:** Launching a safe, reliable v1 beta for real-world peer testing with friends.  
> **Last Updated:** August 2026

---

## 1. Executive Summary & Architecture Overview

Scale is a peer-to-peer WireGuard mesh VPN control plane with STUN-based NAT traversal and automatic WebSocket Relay fallback.

```
                  ┌─────────────────────────────────────────┐
                  │    Scale Control Plane (Go / Fiber)     │
                  │   - Device IPAM (100.64.0.0/16)         │
                  │   - Redis Cache + PostgreSQL Fallback   │
                  │   - Native TLS / HTTPS                  │
                  └────────────────────┬────────────────────┘
                                       │ HTTPS Poll & Heartbeats
           ┌───────────────────────────┴───────────────────────────┐
           ▼                                                       ▼
┌──────────────────────┐        Direct UDP (P2P WireGuard)       ┌──────────────────────┐
│  Friend A (Laptop)   │ ◄─────────────────────────────────────► │  Friend B (Laptop)   │
│  - 100.64.0.x/16     │                                         │  - 100.64.0.y/16     │
│  - Persistent wg.key │ ◄───────────────┐     ┌───────────────► │  - Persistent wg.key │
└──────────────────────┘                 │     │                 └──────────────────────┘
                                         ▼     ▼
                               ┌──────────────────────┐
                               │ Scale Relay (DERP)   │
                               │ - WSS Port 8443      │
                               │ - WebSocket Fallback │
                               └──────────────────────┘
```

---

## 2. Completed v1 Security & Engine Checklist

The following critical items have been verified and built into the codebase:

* [x] **Native TLS Encryption:** Server runs on HTTPS (`app.ListenTLS`), protecting passwords and JWT tokens on the wire.
* [x] **Certificate Verification:** Relay client enforces strict TLS certificate checking (`InsecureSkipVerify: false`).
* [x] **Device Ownership & Auth Gates:** `/api/poll`, `/api/devices/:id/peers`, and `/api/devices/heartbeat` verify that the requesting device is owned by the authenticated JWT user.
* [x] **Persistent Device Identity:** Client securely stores its keypair in `~/.scale/wg.key` (`0600`), preventing IP bloat upon reconnection.
* [x] **Per-Peer Route Flapping Fix (v2 Engine):** Health monitor uses per-peer failure maps, `IpcSet` recovery, and STUN Trickle ICE.
* [x] **Clean Interface Teardown:** Intercepts `SIGINT`/`SIGTERM` to destroy the userspace `wg0` TUN interface cleanly.

---

## 3. Server Deployment Guide (AWS EC2 or Home Laptop)

### Step 3.1: Environment File Configuration (`.env`)
Create a `.env` file in the project root on your host machine / server:

```env
# Server Network Config
PORT=8080
JWT_SECRET=generate_a_random_32_character_string_here
DEVICE_AUTH_SECRET=generate_another_random_secret_here

# PostgreSQL Database (Localhost only)
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USER=scale_user
DB_PASSWORD=your_strong_postgres_password
DB_NAME=scale_db

# Redis Cache (Localhost only)
REDIS_ADDR=127.0.0.1:6379
REDIS_PASSWORD=

# Relay Server Auth Key
DERP_AUTH_KEY=scale_relay_shared_secret_key_123
```

---

### Step 3.2: Database & Redis Initialization

1. **Start PostgreSQL & Redis (Binding only to `127.0.0.1`):**
   ```bash
   sudo systemctl enable --now postgresql
   sudo systemctl enable --now redis-server
   ```

2. **Initialize Database Schema:**
   ```bash
   sudo -u postgres psql -c "CREATE USER scale_user WITH PASSWORD 'your_strong_postgres_password';"
   sudo -u postgres psql -c "CREATE DATABASE scale_db OWNER scale_user;"
   sudo -u postgres psql -d scale_db -f deploy/setup_db.sql
   ```

---

### Step 3.3: TLS Certificate Generation

#### Option A: Quick Self-Signed (Local Testing / IP Deployment)
Generate valid 2048-bit RSA certificate files in the working directory:
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=scale-server"
```
*(Copy `cert.pem` and `key.pem` into `cmd/relay/` as well).*

#### Option B: Production Domain with Let's Encrypt (Recommended for AWS)
If using a domain name (e.g., `scale.yourdomain.com`):
```bash
sudo certbot certonly --standalone -d scale.yourdomain.com
# Copy or symlink fullchain.pem -> cert.pem and privkey.pem -> key.pem
```

---

### Step 3.4: Firewall / Security Group Configuration
Only expose necessary public ports:

| Port | Protocol | Purpose | Access |
|---|---|---|---|
| **8080** | TCP | Control Plane API (HTTPS) | Public (`0.0.0.0/0`) |
| **8443** | TCP | WebSocket Relay Server (WSS) | Public (`0.0.0.0/0`) |
| **51820** | UDP | WireGuard Direct P2P Traffic | Public (`0.0.0.0/0`) |
| **5432** | TCP | PostgreSQL Database | **PRIVATE (`127.0.0.1` only)** |
| **6379** | TCP | Redis Cache | **PRIVATE (`127.0.0.1` only)** |

---

### Step 3.5: Start Server Binaries

```bash
# 1. Build and start Control Plane
go build -o scale-control main.go
./scale-control &

# 2. Build and start Relay Server
go build -o scale-relay ./cmd/relay/main.go
./scale-relay &
```

---

## 4. Client Setup Guide (For Your Friends)

### Step 4.1: Build Client Binary
Build the Linux client binary on your machine or have friends build it:
```bash
go build -o scale-client ./cmd/scale-client
```

---

### Step 4.2: Client Configuration (`.env`)
Create a `.env` file in the same directory as `scale-client`:

```env
# Control Plane & Relay URLs
WG_CONTROL_SERVER=https://<YOUR_SERVER_PUBLIC_IP_OR_DOMAIN>:8080
RELAY_URL=wss://<YOUR_SERVER_PUBLIC_IP_OR_DOMAIN>:8443/derp?auth=scale_relay_shared_secret_key_123

# User Authentication (Friend creates account or uses given credentials)
SCALE_EMAIL=friend1@example.com
SCALE_PASSWORD=friend_secure_password_123

# WireGuard Interface Settings
WG_INTERFACE=wg0
WG_PORT=51820
```

---

### Step 4.3: Running the Client
Because WireGuard creates a kernel TUN interface and configures IP routing, the client **must run with `sudo`**:

```bash
sudo ./scale-client
```

---

## 5. Step-by-Step Real-World Verification Test Suite

Run these tests with your friends to validate all network scenarios:

### Test 1: Enrollment & IP Assignment
1. Friend A runs `sudo ./scale-client`.
2. Verify console logs:
   * `Successfully registered. Assigned IP: 100.64.0.1` (or next pool address).
   * `~/.scale/wg.key` file is created with `0600` permissions.
3. Friend B runs `sudo ./scale-client` on their laptop.
4. Verify Friend B receives an independent IP (e.g., `100.64.0.2`).

---

### Test 2: P2P Tunnel Connectivity (Ping & Data Plane)
From Friend A's terminal:
```bash
# Ping Friend B's overlay IP
ping 100.64.0.2 -c 5
```
**Success criteria:** Ping succeeds with low latency (e.g., `<50ms` on LAN or `<150ms` on regional WAN).

---

### Test 3: Cross-Network NAT Traversal (Home Wi-Fi ↔ Mobile Hotspot)
1. Friend A is on Home Wi-Fi.
2. Friend B connects to a Mobile Hotspot (Jio / Airtel / Vi).
3. Both run `sudo ./scale-client`.
4. Observe STUN Trickle ICE candidate discovery:
   * Client logs: `Trickle ICE: STUN public candidate (...:51820) sent to server`
   * Peer logs: `Smart Trust: Peer moved to ...`
5. Test pings across the cellular network.

---

### Test 4: Relay Fallback Simulation
1. Block direct UDP traffic on one client to simulate a strict symmetric firewall:
   ```bash
   sudo iptables -A OUTPUT -p udp --dport 51820 -j DROP
   ```
2. Observe `scale-client` console:
   * `udp peer is dead (last pong > 15s)`
   * `udp failed! shifting to relay`
   * `switched to relay`
3. Ping Friend B:
   ```bash
   ping 100.64.0.2
   ```
   **Success criteria:** Pings continue to flow through the WebSocket Relay (latency will rise to ~200-400ms, but zero dropped packets).
4. Restore UDP:
   ```bash
   sudo iptables -D OUTPUT -p udp --dport 51820 -j DROP
   ```
   * Observe recovery: `udp recovered, switching back to direct connection`.

---

### Test 5: Idempotency & Reconnect Test
1. Press `Ctrl+C` on Friend A's laptop.
2. Verify `wg0` interface is removed cleanly:
   ```bash
   ip link show wg0
   # Should output: "Device 'wg0' does not exist."
   ```
3. Restart the client: `sudo ./scale-client`.
4. **Verify:**
   * It loads the existing `~/.scale/wg.key`.
   * Server returns `Device already registered` and assigns the **exact same `100.64.0.1` IP**.

---

## 6. Troubleshooting Runbook

| Problem | Cause | Solution |
|---|---|---|
| **`x509: certificate signed by unknown authority`** | Client connecting to self-signed server cert without trusted root. | Ensure client has `cert.pem` in working directory or use Let's Encrypt on domain. |
| **`RTNETLINK answers: File exists`** | Previous `wg0` interface or route was not torn down after unexpected crash. | Run `sudo ip link delete wg0` manually, then restart. |
| **`DERP auth key mismatch / 401`** | `RELAY_URL` in `.env` is missing `?auth=<key>` or key does not match server. | Align `DERP_AUTH_KEY` in server `.env` and `RELAY_URL` in client `.env`. |
| **`Auto-login failed: 401 Unauthorized`** | User account does not exist or password mismatch. | Register user first via `POST /api/register` or supply valid `AUTH_TOKEN`. |

---

## 7. Deferred Items (v2 Roadmap for Interviews)

These items are deliberately slated for v2 to keep the v1 beta lightweight and easy to audit:

1. **Access / Refresh Token Rotation & Redis Blocklist:** Dual-token rotation (`internal/util/tokenutil.go`) with automated background refresh.
2. **OS Native Keyrings:** Integrating macOS Keychain / Linux Secret Service instead of `0600` config files.
3. **Privileged Daemon Separation:** Splitting the monolithic `sudo` binary into an unprivileged CLI interacting with a background systemd root daemon via Unix domain sockets.
