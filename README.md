# Scale

Scale is a **Tailscale-alternative mesh VPN** built from scratch in Go. It creates a WireGuard-based overlay network where devices authenticate against a central control server, discover each other's endpoints, and establish encrypted peer-to-peer tunnels — with automatic fallback to a WebSocket relay when direct UDP connectivity fails.

> [!WARNING]
> **Proof of Concept.** This project is a learning build, not production software. See [Known Limitations](#known-limitations-poc-state) before relying on it for anything real.

---

## Overview

Scale is made of three cooperating binaries:

- **Control server** (`main.go`) — a Fiber HTTP API that handles user/device authentication, IP allocation, and peer-discovery via a poll model. Backed by PostgreSQL (source of truth) and Redis (cache, IP pool, live endpoints).
- **Relay server** (`cmd/relay`) — a DERP-style WebSocket relay used as a fallback data path when two peers can't establish a direct UDP tunnel (symmetric NAT, restrictive firewalls, etc).
- **Client** (`cmd/scale-client`) — a userspace WireGuard engine with a custom dual-path transport (`HybridBind`) that can move traffic between direct UDP and the WebSocket relay, plus STUN-based NAT discovery, hole punching, and a health monitor that drives automatic failover/recovery.

---

## Features

- Full control-plane + relay + client implementation in Go, no forked WireGuard tooling
- JWT-based user auth (bcrypt passwords) and device registration tied to a user account
- IP address allocation from a Redis-backed pool, currently sized as a `/16` (65,534 usable addresses)
- STUN-based public endpoint discovery (`stun.l.google.com:19302`) and UDP hole punching
- Custom `HybridBind` transport: a single `conn.Bind` that speaks both raw UDP and WebSocket, so WireGuard doesn't know or care which path is active
- Health monitoring with automatic UDP → relay failover and relay → UDP recovery
- Peer roaming detection (updates a peer's endpoint on the fly when its address changes)
- PostgreSQL fallback for peer/poll lookups if the Redis cache is cold or unavailable

---

## Control Server

The control server is the coordination plane only — it never forwards user traffic. It manages identity, IP allocation, and peer discovery so that clients can find each other and connect directly (or via relay).

| Component | Technology |
|-----------|-----------|
| HTTP framework | [Fiber](https://gofiber.io/) |
| Primary datastore | PostgreSQL via GORM |
| Cache / ephemeral state | Redis |
| Auth | JWT (HS256) + bcrypt password hashing |

### Data Flow

1. **Device registration** — client sends its WireGuard public key; the server allocates an IP from the pool and persists the device in PostgreSQL.
2. **Heartbeat** — client periodically reports its local IPs and STUN-derived public `ip:port`; stored in Redis with a 90s TTL (`device:endpoints:<pubkey>`).
3. **Poll** — client fetches all peers and their cached endpoints, then builds its local WireGuard peer config.
4. **Device cache** — all devices are cached in Redis (`cache:all_devices`) on a synchronous warmup at boot, then refreshed every 10s by a background goroutine, with a PostgreSQL fallback if the cache is missing.

### Database Schema

**PostgreSQL** (GORM auto-migrate)

| Table | Fields |
|-------|--------|
| `users` | id, name, email (unique), password_hash, created_at, updated_at, deleted_at |
| `devices` | id, public_key (unique), assigned_ip (unique), endpoint, user_id, created_at, updated_at, deleted_at |

**Redis keys**

| Key pattern | Type | TTL | Purpose |
|-------------|------|-----|---------|
| `cache:all_devices` | String (JSON) | none (refreshed every 10s by a background goroutine) | Cached device list from PostgreSQL |
| `device:endpoints:<pubkey>` | String (JSON) | 90s | Live endpoint list per device |
| `ip_pool:available` | Set | none | Available IPs for allocation |

---

## Client

A userspace WireGuard client with a custom networking layer designed to keep the tunnel alive across NATs and mid-session network changes. On startup it generates/loads its WireGuard keypair, authenticates against the control server, registers its device to get an assigned IP, brings up the TUN device, and connects to the WebSocket relay. It then runs a poll cycle every 30s: STUN binding request → heartbeat with discovered endpoints → poll for the current peer list → update WireGuard peers via IPC → hole-punch spray to all peer candidate endpoints.

### Key mechanisms

- **HybridBind** (`internal/vpn/hybrid.go`) — a custom `conn.Bind` implementation for WireGuard that handles both UDP (direct P2P) and WebSocket (relay) simultaneously, so the WireGuard engine is transport-agnostic.
- **STUN discovery** — uses a public STUN server to learn the client's server-reflexive (public) `ip:port`.
- **Endpoint selection priority** — LAN IPs → STUN (srflx) → first available candidate.
- **Hole punching** — sends a 5-round probe spray to all peer candidate endpoints to open NAT mappings.
- **Keepalives** — custom probe packets (magic `0xFF505242` + public key) sent every 5s per peer to maintain NAT bindings and detect liveness.
- **Health monitor** — tracks UDP send/probe failures; once a failure threshold is hit, it flips all peers over to the relay endpoint, and switches back once direct UDP is confirmed alive again.
- **Peer roaming** — detects when a peer's address changes (via probe responses) and updates the WireGuard endpoint dynamically.

### Custom protocol framing

| Protocol | Magic | Purpose |
|----------|-------|---------|
| WireGuard | `0x01`–`0x04` (first byte) | Normal WG handshake/data |
| STUN | `0x2112A442` (bytes 4–8) | NAT discovery |
| Probe / keepalive | `0xFF505242` (bytes 0–4), 36 bytes | Liveness + roaming detection |

---

## Relay Server

A minimal DERP-like WebSocket relay used only when direct UDP fails.

- Listens on `wss://:8443/derp` with TLS
- Auth via a `DERP_AUTH_KEY` query parameter
- Clients register by sending their 32-byte public key
- Packets are routed as `[dest_key(32B) | payload]` → server looks up the destination in its in-memory `clients` map → forwards as `[sender_key(32B) | payload]`
- Ping/pong keepalives with a 60s timeout
- Thread-safe client map cleanup (`sync.Once`)

---

## IP Allocation

- IPs are handed out from a Redis-backed pool (`ip_pool:available`), currently a **`/16`** block (`100.64.0.0/16`, CGNAT range) — 65,534 usable addresses.
- Allocation is an atomic `SPOP` from the Redis set; release is `SADD` back into it.
- Clients configure an on-link kernel route for the full `/16` so peer-to-peer traffic within the pool is reachable.
- **Note:** the pool is (re)initialized from a hardcoded CIDR and is not persisted independently of Redis — if Redis's `ip_pool:available` key is flushed or Redis is reset, the pool is rebuilt from the CIDR rather than reconciled against existing PostgreSQL device records.

---

## Benchmarks

Full raw `iperf3`/`ping` output and environment details for every run are in [`project_info/benchmarks.md`](project_info/benchmarks.md) — this is the most up-to-date signal on how the system actually behaves under load, and it's worth reading in full.

### Summary

| Scenario | Avg. Throughput | Stability | Latency |
|---|---|---|---|
| Direct UDP (loopback) | ~40.0 Gbits/sec | Zero retries, no jitter | — |
| WebSocket relay (loopback) | ~40.2 Gbits/sec | Severe jitter — dips to 934 Kbits/sec | — |
| Cross-NAT WAN (WiFi ↔ cellular) | — | Zero packet loss over 500+ pings | ~0.077 ms avg |

### P2P mesh, direct UDP (local loopback)

Two local WireGuard client instances, direct P2P UDP path, custom Go userspace WireGuard engine (`HybridBind`).

- Sustained **~40.0 Gbits/sec** over a 10-second `iperf3` run, transferring 46.6 GB total
- **Zero retries** for the entire duration — no socket congestion, no packet loss
- Confirms the custom userspace engine can hit maximum theoretical loopback throughput cleanly, and that a previously identified deadlock in `HybridBind` has been resolved

### WebSocket relay fallback (local loopback)

Same two clients, but the direct UDP path is blocked with `iptables` (`DROP udp dpt:51820/51821`), forcing all traffic over the local WebSocket relay (`wss://localhost:8443/derp`).

- **~40.2 Gbits/sec average** over 10 seconds (46.8 GB total) — matches the direct UDP average
- But per-second throughput is **highly unstable**: intervals ranged from a healthy ~40 Gbits/sec down to **934 Kbits/sec**, **1.21 Gbits/sec**, and **2.70 Gbits/sec** in individual 1-second windows
- Root cause: pushing tens of Gbps through WebSocket frames drives heavy per-packet heap allocation in Go, triggering garbage-collector "stop-the-world" pauses and/or TCP window buffer saturation
- **Fix identified (not yet implemented):** `sync.Pool`-based byte-buffer reuse in the relay and in `HybridBind`'s WebSocket send/receive path, to cut allocation rate and relieve GC pressure during high-throughput failover
- This confirms the relay path is functionally correct (the `HealthMonitor` shifted traffic over without dropping the connection) but **not yet performance-stable** at high sustained throughput

### Cross-NAT WAN mesh (WiFi ↔ cellular hotspot)

Two laptops on genuinely separate NATs — one on home Airtel WiFi, one on a Jio mobile hotspot — with the control server and relay deployed on AWS EC2 (Mumbai).

- Direct P2P tunnel established successfully across the two NATs
- **~0.077 ms average latency**, **zero packet loss** over 500+ ping packets
- Confirms the custom `HybridBind` engine and hole-punching spray (`StartHolePunching`) can negotiate a direct UDP session without relay involvement, even across separate NAT boundaries

### Route-flapping discovery during WAN testing

The same WAN test also surfaced a real bug: ping latency oscillated on a near-mathematical ~26–34 second period (170–300ms direct ↔ 600–700ms relay), which is a signature of algorithmic route flapping rather than random cellular packet loss. This led to a full root-cause investigation — a 5-bug chain in the health-monitor/failover logic, the most interesting being a recursive tunnel loop where the VPN's own overlay IP (`100.64.x.x`) was mistakenly reported as a physical network candidate. Full breakdown in [Known Limitations](#known-limitations-poc-state) and [`project_info/healthmonitor_bugchain_v2.md`](project_info/healthmonitor_bugchain_v2.md).

After a clean purge of stale device registrations from PostgreSQL, cross-NAT connectivity was validated as fully stable: exactly 2 active peers, clean relay failover (`udp failed! shifting to relay` → `switched to relay` → tunnel active), and ~0.07ms tunneled latency with zero drops over 500+ packets.

### Control-plane load test

There is also a k6 load-testing script for the HTTP control-plane API at [`benchmark/load-test.js`](benchmark/load-test.js) — see [`benchmark/results.txt`](benchmark/results.txt) for the latest raw run output.

---

## Getting Started

### Prerequisites

- Go 1.23+ (toolchain pinned to 1.24.x in `go.mod`)
- PostgreSQL (control-plane source of truth)
- Redis (cache, IP pool, live endpoint storage)
- WireGuard kernel module or userspace tooling on client machines

### Build

```bash
git clone https://github.com/Sankalprai224/scale.git
cd scale

# Control server
go build -o scale-server ./main.go

# Relay
go build -o relay ./cmd/relay

# Client
go build -o scale-client ./cmd/scale-client
```

### Configuration

The control server and client both read from a `.env` file (via `godotenv`). At minimum you'll need:

```
JWT_SECRET=<random secret>
DEVICE_AUTH_SECRET=<random secret>
DATABASE_URL=<postgres connection string>
REDIS_ADDR=<redis host:port>
PORT=8080
DERP_AUTH_KEY=<shared relay auth key>
RELAY_URL=wss://<relay-host>:8443/derp?auth=<DERP_AUTH_KEY>
```

### Running locally

```bash
# 1. Start the control server
./scale-server

# 2. Start the relay
./relay

# 3. Run a client (register/login flow happens on first run)
./scale-client
```

### Cloud deployment

A full AWS EC2 deployment guide (systemd units, TLS cert generation for the relay, firewall rules, and a smoke test script) is available in [`deploy/README.md`](deploy/README.md).

---

## Known Limitations (PoC State)

> [!WARNING]
> This is a learning/PoC project and is **not production-ready**. Several of these limitations are architectural and would need real design work — not quick patches — to resolve.

- **Configs are unsigned.** Clients trust the control server blindly; there's no signature verification on peer configs, which is an MITM risk.
- **Client keys are ephemeral.** WireGuard keypairs are regenerated on every client restart rather than persisted, so a device's identity/IP binding doesn't survive a restart cleanly.
- **Relay-path throughput is unstable at high load.** Sustained high-throughput traffic over the WebSocket relay produces heavy jitter due to GC pressure from per-packet allocations; the fix (buffer pooling via `sync.Pool`) is identified but not yet implemented.
- **Health-monitor / failover logic has a documented bug chain** (5 root causes identified, fix design in [`project_info/healthmonitor_bugchain_v2.md`](project_info/healthmonitor_bugchain_v2.md)) — deferred to v2 along with a full per-peer state refactor.

---

## License

This project is currently unlicensed. Reach out via GitHub issues for licensing inquiries.
