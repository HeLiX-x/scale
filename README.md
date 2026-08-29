# Scale — Mesh WireGuard VPN

Scale is a **Tailscale-alternative mesh VPN** built from scratch in Go. It creates a WireGuard-based overlay network where devices authenticate against a central control server, discover each other's endpoints, and establish encrypted peer-to-peer tunnels — with automatic fallback to a WebSocket relay when direct UDP connectivity is blocked by Symmetric NAT / Carrier-Grade NAT (CGNAT).

---

## Architecture Overview

Scale is composed of three cooperating binaries:

- **Control Server** (`main.go`) — a high-performance Fiber HTTP API handling user/device authentication, `/16` IP allocation, and peer discovery. Backed by PostgreSQL (persistent source of truth) and Redis (caching, atomic IP pool, live endpoints).
- **Relay Server** (`cmd/relay`) — a DERP-style WebSocket relay providing an encrypted fallback data path when direct UDP connectivity fails across restrictive carrier firewalls.
- **Client** (`cmd/scale-client`) — a userspace WireGuard engine with a custom dual-path transport (`HybridBind`) that seamlessly switches between direct UDP and the WebSocket relay, featuring asynchronous Trickle ICE STUN discovery, continuous roaming detection, bidirectional SmartTrust cache synchronization, and state-gated health monitoring.

```
                    ┌────────────────────────────────────────────────────────┐
                    │                   AWS EC2 (Mumbai)                     │
                    │   sankalp-scale.duckdns.org (Let's Encrypt TLS)        │
                    │  ┌───────────────────────┐  ┌───────────────────────┐  │
                    │  │ Control Server (:8080)│  │ WebSocket Relay(:8443)│  │
                    │  │ (Fiber + PG + Redis)  │  │ (DERP Packet Switch)  │  │
                    │  └───────────────────────┘  └───────────────────────┘  │
                    └─────────────────────────┬──────────────────────────────┘
                                              │ Control & Fallback
                                              │
                    ┌─────────────────────────┴──────────────────────────────┐
                    ▼                                                        ▼
         ┌─────────────────────┐                                  ┌─────────────────────┐
         │      Laptop 1       │ ◄ - - - - - - - - - - - - - - -► │      Laptop 2       │
         │   (e.g., Jio 5G)    │      Direct P2P UDP (51820)      │   (e.g., Jio 4G)    │
         │  Overlay: 100.64.x  │        (Encrypted Noise)         │  Overlay: 100.64.y  │
         └─────────────────────┘                                  └─────────────────────┘
```

---

## Key Features

- **End-to-End Go Implementation**: Full control-plane, DERP relay, and client implementation in pure Go without forking external WireGuard tooling.
- **Scalable `/16` IP Allocation**: Redis-backed atomic IP allocation managing a `/16` CGNAT pool (`100.64.0.0/16`) supporting **65,534 usable device IPs**.
- **Control Plane Resilience**: Synchronous cache warmup (`refreshDeviceCache()`) and automatic PostgreSQL fallback for `/api/poll` and peer configuration lookups.
- **Trickle ICE & STUN Discovery**: Dispatches local candidate endpoints immediately on boot and asynchronously streams public server-reflexive endpoints upon STUN resolution (`stun.l.google.com:19302`).
- **Custom `HybridBind` Dual Transport**: A unified `conn.Bind` that multiplexes raw UDP and TLS WebSocket frames simultaneously, keeping the WireGuard engine transport-agnostic.
- **SmartTrust Dynamic Roaming**: Automatically discovers peer address changes from verified incoming probes and updates WireGuard endpoints on the fly.
- **Two-Way Endpoint Cache Synchronization**: Prevents periodic 30s poll cycles from clobbering live roaming endpoints discovered by SmartTrust.
- **State-Gated Recovery Hysteresis**: Requires 3 consecutive probe pongs before clearing fail counters on dead connections, eliminating flapping on lossy mobile links.
- **Recursive Tunnel Loop Filter**: Enforces address-based CIDR filtering (`100.64.0.0/10`) to prevent the virtual overlay interface from being advertised as a physical endpoint.
- **Productized Zero-Friction CLI**: Dedicated `register`, `login`, `up`, `status`, `peers`, `down`, `logout`, and `bugreport` commands with secure `0600` credential management.

---

## Production Cloud Deployment

The live control plane and WebSocket relay are deployed on AWS EC2 with automated systemd lifecycle management and security hardening.

| Component | Specification / Setting | Details |
|---|---|---|
| **Cloud Host** | AWS EC2 `t3.micro` | Ubuntu 24.04 LTS (Region: `ap-south-1` Mumbai) |
| **Domain & DNS** | DuckDNS Dynamic DNS | `sankalp-scale.duckdns.org` $\rightarrow$ Elastic IP |
| **TLS / HTTPS** | Let's Encrypt via Certbot | Automated SSL certificates on `:8443` (WSS) and `:8080` |
| **Primary Database** | PostgreSQL 16 | Bound strictly to `127.0.0.1:5432` |
| **Cache & IP Pool** | Redis 7 | Bound strictly to `127.0.0.1:6379` (`protected-mode yes`) |
| **Firewall** | UFW (Uncomplicated Firewall) | Default Inbound Deny; Ingress allowed only on `22/tcp`, `8080/tcp`, `8443/tcp`, `51820/udp` |
| **Process Supervision** | Systemd System Services | `scale-control.service` & `scale-relay.service` (auto-start on boot) |

### Infrastructure Hardening Guarantee
The control plane binary contains hard startup assertions (`database/local_only.go`) that immediately abort execution if `DATABASE_URL` or `REDIS_ADDR` resolve to anything other than loopback (`127.0.0.1`, `localhost`, `::1`), eliminating the risk of accidental exposure to the public internet.

---

## Productized CLI Reference

The `scale` CLI provides a complete user experience for enrolling devices, starting sessions, and diagnosing mesh health.

```bash
Scale VPN — mesh WireGuard client

Usage:
  scale <command>

Commands:
  register    Create a new user account & log in
  login       Interactive login; saves JWT to ~/.scale/token
  up          Start VPN tunnel, poller, and health monitor
  status      Show client status, assigned IP, and relay state
  peers       Table of mesh peers and ping status
  down        Stop VPN session and remove wg0
  logout      Clear local token and credentials
  bugreport   Write a redacted diagnostic snapshot
  version     Show build version, git commit, and architecture
```

### Local State & Security Architecture
All local state is stored in `~/.scale/` with strict POSIX permissions (`0700` directory, `0600` credential files). The CLI resolves paths via `SUDO_USER`, allowing `scale register`/`login` (run as normal user) to write credentials that are seamlessly read by `sudo scale up`.

| File Path | Permissions | Purpose |
|---|:---:|---|
| `~/.scale/token` | `0600` | Stored JWT token from authentication |
| `~/.scale/wg.key` | `0600` | Persistent WireGuard private key |
| `~/.scale/config.json` | `0600` | Default control server and relay endpoints |
| `~/.scale/scale.sock` | `0660` | UNIX domain socket for non-root IPC status queries |
| `~/.scale/scale.pid` | `0644` | Active daemon process PID |
| `~/.scale/status.json` | `0644` | Atomic runtime snapshot for telemetry |

---

## Validated Performance Benchmarks

Comprehensive benchmarks were executed across three real-world topologies:
1. **Local Kernel Loopback** (`127.0.0.1` high-throughput data-plane test)
2. **2-Node Cross-Carrier Cellular WAN** (Jio 5G $\leftrightarrow$ Jio 4G via AWS Mumbai Relay)
3. **3-Node Multi-Carrier & Cross-Platform Mesh** (Ubuntu 24.04 Linux on Jio 5G Phone Hotspot $\leftrightarrow$ Windows 11 WSL2 on Airtel Home Fiber $\leftrightarrow$ Arch Linux on a separate Jio 4G Phone Hotspot)

Full raw logs, test outputs, and socket traces are recorded in [`project_info/project overview and benchmark results/benchmarks.md`](project_info/project%20overview%20and%20benchmark%20results/benchmarks.md).

### Performance Comparison Matrix

| Benchmark Metric | Local Loopback (`wg0` $\leftrightarrow$ `wg1`) | Jio 5G Hotspot $\leftrightarrow$ Airtel Fiber (Windows WSL2) | Jio 5G Hotspot $\leftrightarrow$ Jio 4G Hotspot (Arch Linux) |
|---|:---:|:---:|:---:|
| **Physical Topology** | Kernel Loopback (`127.0.0.1`) | Cellular 5G Phone $\leftrightarrow$ Home Residential Fiber | Separate 5G Phone $\leftrightarrow$ Separate 4G Phone (Dual Mobile CGNAT) |
| **OS Platforms** | Ubuntu Linux $\leftrightarrow$ Ubuntu Linux | Ubuntu 24.04 $\leftrightarrow$ Windows 11 (WSL2) | Ubuntu 24.04 $\leftrightarrow$ Arch Linux (Rolling) |
| **Active Transport** | Direct UDP (Loopback) | WebSocket Relay (AWS Mumbai) | WebSocket Relay (AWS Mumbai) |
| **Route Stability** | 100% Stable (0 Flaps) | **100% Stable (0 Flaps)** | **100% Stable (0 Flaps)** |
| **ICMP Packet Loss** | 0.0% | **2.0% (49 / 50 delivered)** | **8.0% (46 / 50 delivered)** |
| **Average Latency (RTT)** | 0.077 ms | **119.99 ms** | **372.28 ms** |
| **Jitter (`mdev`)** | $< 0.1$ ms | **19.58 ms** *(Telecom-grade < 30ms SLA)* | **75.14 ms** |
| **1420-Byte MTU Integrity** | 100% Intact | **0.0% Loss (10 / 10 delivered)** | **0.0% Loss (10 / 10 delivered)** |
| **TCP Throughput (Forward)** | **40.0 Gbps** | ~3.56 Mbps (Cellular Uplink Constrained) | ~3.56 Mbps (6.29 Mbps peak) |
| **TCP Retransmissions** | 0 | **0 Retransmissions (`Retr: 0`)** | **0 Retransmissions (`Retr: 0`)** |
| **UDP Stream Loss Rate** | 0.0% | **0.0% (0 / 4,568 packets)** | **0.0% (0 / 4,568 packets)** |
| **Client Memory Footprint (RSS)**| ~23.4 MB | **23.9 MB** | **23.9 MB** |
| **Client CPU Utilization** | $< 0.5\%$ | **0.5% (Idle / Steady State)** | **0.5% (Idle / Steady State)** |

### Detailed Test Summaries

1. **Simultaneous 3-Node Multi-Carrier Mesh**: Enrolled 3 physical devices across 3 isolated networks into a single private `/16` overlay (`100.64.0.0/16`):
   - **Node 1 (Local):** Ubuntu 24.04 Linux tethered to a **Jio 5G Mobile Hotspot (Phone 1)**.
   - **Node 2:** Windows 11 running **WSL2** connected to **Airtel Residential Fiber Broadband**.
   - **Node 3:** Arch Linux laptop tethered to an independent **Jio 4G Mobile Hotspot (Phone 2)**.
   All 3 devices established simultaneous, bidirectional 3-way routing with sub-second keepalive liveness.
2. **Telecom-Grade Low Jitter (`19.58 ms`)**: 50-packet rapid stream across Jio 5G and Airtel Broadband achieved an average latency of 119.9 ms and 19.58 ms jitter—well within the $< 30$ ms SLA for real-time VoIP, gaming, and interactive SSH.
3. **WireGuard MTU Clamping (1420 Bytes)**: Full-size 1392-byte ICMP payloads (1420-byte WireGuard frames) achieved 0.0% packet loss across all carriers and OS environments, proving zero Path MTU (PMTU) black holes or fragmentation drops.
4. **Lightweight Daemon Footprint**: The userspace WireGuard engine, `HybridBind` dual transport, Trickle ICE STUN poller, and UNIX IPC daemon maintain a steady-state footprint of **~23.4 MB RAM (RSS)** and **0.5% CPU**.
5. **TCP Throughput & Zero Retransmissions**: Sustained 3.56 Mbps throughput with **zero TCP retransmissions** (`Retr: 0`), smooth congestion window scaling (37.4 KB $\rightarrow$ 399 KB), and 100% bit-perfect 10MB binary payload transfers.

---

## Real-World Use Cases

Scale provides a flat, encrypted virtual network (`100.64.0.0/16`) where all enrolled devices communicate as if they are on the same local switch:

- **Localhost & API Sharing (ngrok Alternative)**: Expose local development servers (`localhost:3000`) directly to teammates over `100.64.x.x` without public URLs, data caps, or third-party proxies.
- **Remote Database Access**: Connect GUI tools (DBeaver, pgAdmin, Compass) on one machine directly to local databases on another machine over private encrypted channels.
- **Homelab & Remote SSH**: SSH into home servers or development rigs (`ssh user@100.64.x.x`) from coffee shops or mobile networks without port forwarding.
- **Virtual LAN Gaming**: Play multiplayer LAN games (Minecraft, CS, retro emulators) with friends across different physical locations with direct IP connect.
- **Direct P2P File Transfers**: Transfer multi-gigabyte datasets directly using standard tools (`scp`, `rsync`, LocalSend, or GUI SFTP) without cloud intermediate storage.
- **Remote Game Streaming**: Stream high-end AAA games from a heavy GPU rig to a thin-and-light laptop at 60–120 FPS using **Sunshine** and **Moonlight** over the private overlay.

---

## Quickstart Guide

### 1. Installation

```bash
git clone https://github.com/Sankalprai224/scale.git
cd scale
./install.sh
```

### 2. Register or Log In

For a new account:
```bash
scale register
```

Or log in to an existing account:
```bash
scale login
```

### 3. Connect to the Mesh

```bash
sudo scale up
```

### 4. Inspect Status and Peers

In a second terminal:
```bash
# Check client health and transport mode
scale status

# View mesh peer table and live ping latency
scale peers

# Test direct ping
ping 100.64.x.x
```

### 5. Disconnect

```bash
sudo scale down
```

---

## Self-Hosting / Server Setup

To deploy your own control plane and WebSocket relay on an Ubuntu server:

```bash
# 1. Clone repository
git clone https://github.com/Sankalprai224/scale.git
cd scale

# 2. Configure environment
cp .env.example .env
# Edit .env with your PostgreSQL credentials, JWT secrets, and domain name

# 3. Apply security hardening (bind DBs to 127.0.0.1 & configure UFW)
sudo ./deploy/harden.sh

# 4. Build binaries
go build -o scale-server ./main.go
go build -o relay ./cmd/relay

# 5. Run services (or configure via systemd)
./scale-server &
./relay &
```

---

## License

MIT — see [LICENSE](LICENSE).


