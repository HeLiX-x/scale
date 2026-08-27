# Scale

Scale is a **Tailscale-alternative mesh VPN** built from scratch in Go. It creates a WireGuard-based overlay network where devices authenticate against a central control server, discover each other's endpoints, and establish encrypted peer-to-peer tunnels — with automatic fallback to a WebSocket relay when direct UDP connectivity is blocked by Symmetric NAT / CGNAT.

---

## Overview

Scale is composed of three cooperating binaries:

- **Control Server** (`main.go`) — a Fiber HTTP API that handles user/device authentication, `/16` IP allocation, and peer discovery via a poll model. Backed by PostgreSQL (source of truth) and Redis (cache, dynamic IP pool, live endpoints).
- **Relay Server** (`cmd/relay`) — a DERP-style WebSocket relay used as a fallback data path when direct UDP connectivity fails across restrictive carrier NATs.
- **Client** (`cmd/scale-client`) — a userspace WireGuard engine with a custom dual-path transport (`HybridBind`) that can move traffic between direct UDP and the WebSocket relay, featuring asynchronous Trickle ICE STUN discovery, continuous roaming detection, bidirectional SmartTrust cache synchronization, and state-gated health monitoring.

---

## Key Features

- **End-to-End Go Implementation**: Full control-plane, DERP relay, and client implementation in pure Go without forking WireGuard tooling.
- **Scalable `/16` IP Allocation**: Redis-backed atomic IP allocation managing a `/16` CGNAT pool (`100.64.0.0/16`) supporting **65,534 usable device IPs**.
- **Control Plane Resilience**: Synchronous cache warmup (`refreshDeviceCache()`) and automatic PostgreSQL fallback for `/api/poll` and peer configuration lookups.
- **Trickle ICE & STUN Discovery**: Dispatches local candidate endpoints immediately on boot and asynchronously streams public server-reflexive endpoints upon STUN resolution (`stun.l.google.com:19302`).
- **Custom `HybridBind` Dual Transport**: A unified `conn.Bind` that multiplexes raw UDP and TLS WebSocket frames simultaneously, keeping the WireGuard engine transport-agnostic.
- **SmartTrust Dynamic Roaming**: Automatically discovers peer address changes from verified incoming probes and updates WireGuard endpoints on the fly.
- **Two-Way Endpoint Cache Synchronization**: Prevents periodic 30s poll cycles from clobbering live roaming endpoints discovered by SmartTrust.
- **State-Gated Recovery Hysteresis**: Requires 3 consecutive probe pongs before clearing fail counters on dead connections, eliminating flapping on lossy mobile links.
- **Recursive Tunnel Loop Filter**: Enforces address-based CIDR filtering (`100.64.0.0/10`) to prevent the virtual overlay interface from being advertised as a physical endpoint.

---

## Control Server

The control server manages identity, IP allocation, and peer coordination without proxying data traffic.

| Component | Technology | Description |
|---|---|---|
| HTTP framework | [Fiber](https://gofiber.io/) | High-performance Go web framework |
| Primary datastore | PostgreSQL via GORM | Persistent source of truth for users and devices |
| Cache / ephemeral state | Redis | In-memory cache, atomic `/16` IP pool, and candidate endpoints |
| Authentication | JWT (HS256) + bcrypt | Stateless user and device authorization |

### Data Flow

1. **Device Registration** — Client sends WireGuard public key; server allocates an IP atomically via `SPOP` from `ip_pool:available` and persists the device in PostgreSQL.
2. **Heartbeat** — Client reports local physical endpoints and STUN-derived public `ip:port`; validated against JWT user ownership and stored in Redis with a 90s TTL (`device:endpoints:<pubkey>`).
3. **Poll** — Client queries `/api/poll` to fetch all peers and candidate endpoints, falling back to PostgreSQL if Redis is cold.
4. **Device Cache Warmup** — All devices are cached in Redis (`cache:all_devices`) synchronously at boot, then refreshed every 10s by a background worker.

---

## Client Architecture

A userspace WireGuard client designed for seamless resilience across cellular NAT boundaries and roaming events.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Control Server
    participant STUN as Google STUN
    participant R as Relay (AWS)

    C->>C: Load/Generate WireGuard Keypair
    C->>S: POST /api/login (JWT)
    C->>S: POST /api/devices/register (Allocates 100.64.x.x/16)
    C->>C: Create TUN Interface (wg0) & configure /16 route
    C->>R: Connect WebSocket Relay (wss://:8443/derp)
    C->>C: Start HybridBind & Userspace WireGuard Engine
    C->>S: Immediate Heartbeat with Local Host IPs (excluding 100.64.0.0/10)
    C->>STUN: Async STUN Probe (Trickle ICE)
    STUN-->>C: STUN Public Endpoint (srflx)
    C->>S: Secondary Heartbeat with STUN Endpoint
    loop Every 30s (Poll Cycle)
        C->>S: GET /api/poll
        S-->>C: Active peer list & endpoints
        C->>C: Update WireGuard IPC & preserve SmartTrust endpoints
        C->>C: 5-round hole punching spray to candidates
        C->>C: Start dynamic keepalives per peer (IpMap lookup)
    end
```

### Custom Protocol Framing

| Protocol | Magic Header | Size | Purpose |
|---|---|---|---|
| WireGuard | `0x01`–`0x04` (first byte) | Variable | WireGuard handshake and encrypted transport |
| STUN | `0x2112A442` (bytes 4–8) | Variable | Public NAT discovery |
| Probe / Keepalive | `0xFF505242` (bytes 0–4) | 36 bytes | Liveness, latency tracking, and roaming detection |

---

## Relay Server

A high-throughput **DERP-style** WebSocket relay used when direct UDP is blocked by Symmetric NAT / CGNAT:

- Listens on `wss://:8443/derp` with TLS encryption.
- Authenticated via `DERP_AUTH_KEY` query parameter.
- Routes packets: `[dest_key(32B) | payload]` $\rightarrow$ looked up in memory map $\rightarrow$ forwarded as `[sender_key(32B) | payload]`.
- End-to-end encrypted: the relay operates solely on ciphertext; payloads are decrypted only by destination WireGuard endpoints.

---

## Validated Performance Benchmarks

Full raw outputs, `iperf3` logs, and topology details are documented in [`project_info/project overview and benchmark results/benchmarks.md`](project_info/project%20overview%20and%20benchmark%20results/benchmarks.md).

### Live Cross-WAN Cellular Results (Jio 5G $\leftrightarrow$ Jio 4G via AWS Mumbai Relay)

| Benchmark Metric | Test Conditions | Result | Key Significance |
|---|---|:---:|---|
| **Route Stability** | 100 ICMP packets over 100s | **96% Delivery / 0 Flaps** | Flapping bug permanently resolved |
| **Round-Trip Latency** | Double cellular hop via AWS | **333.3 ms avg (165.9 ms min)** | Consistent cross-carrier transit |
| **Forward TCP Throughput** | 10s `iperf3` Stream (5G $\rightarrow$ 4G) | **3.56 Mbps (6.29 Mbps peak)** | **0 TCP Retransmissions** (`Retr: 0`) |
| **UDP Jitter & Loss** | 5.00 Mbps Stream (4,568 pkts) | **0.0% Loss / 8.12 ms Jitter** | Telecom-grade timing for VoIP/SSH |
| **Reverse TCP Throughput** | 10s `iperf3` Stream (4G $\rightarrow$ 5G) | **1.15 Mbps (4.19 Mbps peak)** | **0 TCP Retransmissions** on 4G uplink |
| **HTTP Application Traffic** | Chrome Browser Directory Listing | **HTTP 200 OK** | Full Layer 7 web rendering over VPN |
| **10MB Binary Transfer** | Continuous `curl` streaming | **100% Bit-Perfect (105s duration)** | Zero resets under continuous load |

---

## Getting Started

### Prerequisites

- Go 1.23+ (toolchain pinned to 1.24.x in `go.mod`)
- PostgreSQL (control-plane datastore)
- Redis (cache, IP pool, live endpoint storage)
- Linux machine with `sudo` permissions (for WireGuard TUN device creation)

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

### Configuration (`.env`)

```env
JWT_SECRET=<random base64 secret>
DEVICE_AUTH_SECRET=<random base64 secret>
DATABASE_URL=postgres://scale_user:password@localhost:5432/scale_db?sslmode=disable
REDIS_ADDR=localhost:6379
PORT=8080
DERP_AUTH_KEY=<shared relay auth key>
RELAY_URL=wss://<relay-host>:8443/derp?auth=<DERP_AUTH_KEY>
WG_CONTROL_SERVER=http://<control-host>:8080
SCALE_EMAIL=user@example.com
SCALE_PASSWORD=password123
```

### Running Locally

```bash
# 1. Start the control server
./scale-server

# 2. Start the relay
./relay

# 3. Run client with root privileges
sudo ./scale-client
```

---

## License

MIT — see [LICENSE](LICENSE).

