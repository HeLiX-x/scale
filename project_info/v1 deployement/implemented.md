# Scale VPN v1 CLI — Implementation Log

Logged as each productization item from `project_info/still left to do/v1_todo.md` was added.

---

## 1. CLI foundation & `~/.scale/` credential storage

**Files:** `cmd/scale-client/main.go`, `cmd/scale-client/config.go`

Replaced the single `main()` entrypoint (`sudo ./scale-client`) with a structured command dispatcher:

```
scale login | up | status | peers | down | logout | bugreport | version
```

State directory is always the invoking user's home, including under `sudo` (`SUDO_USER` → that user's `~/.scale`), so a token written by `scale login` is visible to `sudo scale up`.

| Path | Mode | Purpose |
|---|---|---|
| `~/.scale/` | `0700` | Owner-only state dir; chowned back to invoker after sudo writes |
| `~/.scale/token` | `0600` | JWT from `scale login` |
| `~/.scale/wg.key` | `0600` | Persistent WireGuard private key |
| `~/.scale/config.json` | `0600` | Control server + relay URL |
| `~/.scale/scale.sock` | `0660` | Live IPC for status/peers/stop |
| `~/.scale/scale.pid` | `0644` | Running `scale up` pid |

`generateOrLoadKeys()` now uses this path helper instead of `os.UserHomeDir()` (which is `/root` under sudo).

**Code:** `invokerHome()`, `ensureScaleDir()`, `writeSecureFile()`, `readToken()`, `writeToken()`, `loadConfig()`, `saveConfig()`, `chownToInvoker()`.

---

## 2. `scale login`

**Files:** `cmd/scale-client/login.go` (uses existing `loginToServer()` in `setup.go`)

Behavior:

1. Flags `-server` and `-relay`, then `WG_CONTROL_SERVER` / `RELAY_URL`, then `~/.scale/config.json`, then interactive prompt.
2. Prompts for email; password via `golang.org/x/term` (masked, no echo).
3. `POST /api/login` to the control server.
4. Writes JWT to `~/.scale/token` with `0600`.
5. Persists server/relay URLs in `config.json`.
6. Prints: `Login successful! Token saved to ~/.scale/token`.

`scale up` no longer auto-logs in from `SCALE_EMAIL`/`SCALE_PASSWORD`; missing token returns `Please run 'scale login' first`.

---

## 3. `scale up`

**Files:** `cmd/scale-client/setup.go` (`cmdUp`, `runVPN`)

- Requires root (`sudo scale up`); refuses if a pid is already live (idempotent).
- Creates a cancellable **root context** (`vpnCtx` / `vpnCancel`). SIGINT, SIGTERM, and `scale down` all cancel it.
- Loads token from `~/.scale/token`, keys from `~/.scale/wg.key`, URLs from env/config.
- Registers the device, creates TUN `wg0`, starts HybridBind, STUN trickle, poll loop, and health monitor — all under that context + `sync.WaitGroup`.
- Keepalive goroutines are children of `vpnCtx` (not detached `context.Background()`). Peers that disappear from a poll have their keepalive cancelled.
- Writes pid + unix socket. Publishes a live snapshot for `status`/`peers`.
- Leftover `wg0` from a crash: one `ip link delete` retry before `CreateTUN`.
- Blocks until cancel, then `teardownVPN()`.

---

## 4. Lifecycle teardown (`scale down` + Ctrl+C)

**Files:** `cmd/scale-client/down.go`, `teardownVPN()` in `setup.go`

`teardownVPN()`:

1. Cancels every keepalive.
2. Closes the userspace WireGuard device.
3. `bind.Shutdown()` (UDP + WebSocket); `RunControlLoop` now exits on `closeChan`.
4. `ip link delete <iface>` — removing `wg0` drops the `/16` overlay route and restores the kernel table.
5. Removes pid, socket, and status file.

`scale down` (root required):

1. Sends `{"cmd":"stop"}` on the unix socket (fallback: SIGINT to pid, then Kill).
2. Waits up to 5s for the process to exit.
3. Deletes `wg0` again as a safety net (idempotent if already gone).
4. Prints: `Scale VPN disconnected. Network interface wg0 removed.`

`HybridBind.RunControlLoop` was changed from `for range ControlChan` (never exited) to `select` on `closeChan` so `down` actually joins that worker.

---

## 5. `scale status`

**Files:** `cmd/scale-client/status.go`, snapshot in `setup.go` / `ipc.go`

Live snapshot over `~/.scale/scale.sock`, fallback `~/.scale/status.json`. If neither exists:

```
Status:           DISCONNECTED
```

When connected, matches the spec layout:

```
Scale VPN Client (v1.0.0)
--------------------------------------------------
Status:           CONNECTED (Tunnel active)
Interface:        wg0
Overlay IP:       100.64.0.2/16
Public Key:       aBCdEFgH... (fingerprint, first 8 chars)
Control Server:   https://… (OK|DOWN)     — query string stripped
Relay Server:     wss://… (Connected)     — `?auth=` stripped
NAT Type:         Easy / Port-Preserving  — STUN port == listen port
Active Peers:     N online
```

Relay-fallback status line is `CONNECTED (Relay fallback)`.

New HybridBind helpers: `RelayConnected()`, `LastPong()`, `SnapshotPongs()`.

---

## 6. `scale peers`

**Files:** `cmd/scale-client/status.go` (`cmdPeers`), `publishSnapshot()` in `setup.go`

ASCII table:

```
PEER IP        PUBLIC KEY    TRANSPORT       LAST PONG    STATUS
100.64.0.1     x8K2mN9...    Direct UDP      2s ago       HEALTHY
100.64.0.3     p4L9vB1...    WebSocket Relay 4s ago       HEALTHY (Relay)
```

- Transport is Direct UDP vs WebSocket Relay from `IsPeerUdpDead` / health-monitor relay mode.
- STATUS: pong ≤10s HEALTHY / HEALTHY (Relay); ≤20s DEGRADED; else OFFLINE.
- Overlay IP taken from poll `peer.ID` (assigned CGNAT address).

If VPN is down: `Scale VPN is not running. Start it with 'sudo scale up'.`

---

## 7. `scale logout`

**Files:** `cmd/scale-client/login.go` (`cmdLogout`)

1. Deletes `~/.scale/token`.
2. If `wg.key` exists, prompts `Delete WireGuard identity (~/.scale/wg.key)? [y/N]`.
3. Prints: `Logged out successfully. Local credentials cleared.`

---

## 8. `scale bugreport`

**Files:** `cmd/scale-client/bugreport.go`

Writes `~/.scale/bugreport-YYYYMMDD-HHMMSS.txt` (`0600`) and prints the same text.

**Collected:** OS/kernel (`uname -a`, `/etc/os-release`), `ip link` / `ip addr show dev wg0` / `ip route`, pid, NAT type, peer count, redacted control/relay URLs, token/key presence (not contents), allowlisted env (`WG_INTERFACE`, `WG_PORT`, URLs with query stripped).

**Redaction:** JWT file contents, `wg.key` bytes, `Authorization: Bearer …`, `AUTH_TOKEN`, `SCALE_PASSWORD`, `JWT_SECRET`, `DEVICE_AUTH_SECRET`, `DERP_AUTH_KEY`, `DB_PASSWORD`, `REDIS_PASSWORD`, `DATABASE_URL`. Relay `?auth=` never copied into the report.

---

## 9. `scale version`

**Files:** `cmd/scale-client/main.go`

```
Scale VPN Client v1.0.0
  Git commit:  <ldflags or dev>
  Built:       linux/amd64
  Go:          go1.x
```

`install.sh` injects:

```
-X main.Version=$(git describe …) -X main.GitCommit=$(git rev-parse --short HEAD)
```

---

## 10. Runtime IPC & snapshot

**Files:** `cmd/scale-client/ipc.go`, `internal/vpn/hybrid.go`

Unix socket protocol (one JSON request/response per connection):

- `{"cmd":"status"}` → full `RuntimeSnapshot`
- `{"cmd":"peers"}` → `[]PeerSnap`
- `{"cmd":"stop"}` → cancels root context (same path as Ctrl+C)

Snapshot is also written to `~/.scale/status.json` (no secrets) so `status`/`peers` work as the non-root user while `up` is running as root. Socket is `0660` and chowned to `SUDO_USER`.

Health monitor `usingRelay` is now `atomic.Bool` so status can read it without racing the failover loop.

---

## 11. `install.sh` / `uninstall.sh`

**Files:** `install.sh`, `uninstall.sh` (repo root, executable)

`install.sh`:

1. `go build -ldflags … -o scale ./cmd/scale-client`
2. `sudo mv scale /usr/local/bin/scale && chmod +x`
3. `mkdir -p ~/.scale && chmod 700` (respects `SUDO_USER`)

`uninstall.sh`:

1. `sudo ip link delete wg0` (ignore if missing)
2. `sudo rm -f /usr/local/bin/scale`
3. `rm -rf ~/.scale` (invoking user's home, not `/root` under sudo)

---

## 12. Dependency

Direct require: `golang.org/x/term v0.31.0` (masked password input). Go language version left at `1.23.1` / toolchain `go1.24.7`.

---

## 13. Section 5 — localhost Postgres/Redis, firewall, secrets out of git

### PostgreSQL & Redis on `127.0.0.1`

**Files:** `database/local_only.go`, `database/database.go`, `database/redis.go`, `deploy/bind_localhost.sh`

Control plane refuses to boot unless `DATABASE_URL` and `REDIS_ADDR` resolve to loopback (`127.0.0.1`, `localhost`, `::1`). Empty Redis addr defaults to `127.0.0.1:6379`.

`deploy/bind_localhost.sh` (root) sets `listen_addresses = 'localhost'` in PostgreSQL, `bind 127.0.0.1 ::1` + `protected-mode yes` in Redis, then restarts both.

### Restricted firewall

**Files:** `deploy/setup_firewall.sh`, `deploy/harden.sh`, `deploy/README.md`

UFW: default deny inbound; allow `22/tcp`, `8080/tcp`, `8443/tcp`, `51820/udp`; deny `5432/tcp` and `6379/tcp`. `harden.sh` runs bind + firewall.

### Secrets out of git

**Files:** `.gitignore`, `.env.example`

- Ignore `.env`, `.env.*` (except `.env.example`), `*.pem`, `*.key`, `cookies.txt`.
- Untracked previously committed secrets: `git rm --cached cookies.txt cmd/relay/cert.pem cmd/relay/key.pem` (files kept on disk).
- Root-only binary ignores (`/scale-client`) so `cmd/scale-client` source is not ignored.
- `.env.example` is placeholders only (`127.0.0.1` for DB/Redis).
