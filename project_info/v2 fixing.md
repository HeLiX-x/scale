# Scale VPN — v2 Fixing Log
> Applied locally against `vpn_v2_fix_report.md` (2026-08-27)

---

## Bug 6 — Per-peer health counters (`HybridBind` maps)

**File:** `internal/vpn/hybrid.go`  
**Status:** DONE

Replaced global scalars `udpFailCount` and `lastPongTime` with per-peer maps:

- `failCounts map[string]int`
- `successCounts map[string]int`
- `lastPongs map[string]time.Time`

Initialized in `NewHybridBind()`. Added `IsPeerUdpDead(peerKeyHex string)`. Kept `IsUdpDead()` as “any peer at threshold” so `HealthMonitor()` still works.

---

## Bug 2 — False reset in `Send()`

**File:** `internal/vpn/hybrid.go` — `Send()`  
**Status:** DONE

Removed `udpFailCount = 0` on successful `WriteToUDP`. Local OS buffer accept is not proof of remote delivery.

On actual write errors, increment `failCounts[peerKey]` (via `peerKeyForAddr`) and zero `successCounts[peerKey]`. Fail counts are otherwise only cleared by verified pongs in `RunControlLoop()`.

---

## Bug 3 — `StartKeepAlives` locked to stale LAN IP

**File:** `internal/vpn/hybrid.go` — `StartKeepAlives()`  
**Caller:** `cmd/scale-client/setup.go` — `performPollCycle()`  
**Status:** DONE

Signature is now `StartKeepAlives(ctx, peerKeyHex, initialAddr)`. Each tick looks up `IpMap[peerKeyHex]` and falls back to `initialAddr`. Dead-peer mark writes `failCounts[peerKeyHex] = 5` (not a global counter). Caller passes `hexPeerKey`.

---

## Bug 8 — Recovery hysteresis (gated, per-peer)

**File:** `internal/vpn/hybrid.go` — `RunControlLoop()`  
**Status:** DONE

When `failCounts[peerKey] >= threshold`, require 3 consecutive pongs (`successCounts[peerKey] >= 3`) before clearing dead state. If already healthy, a pong zeros fail/success counts immediately.

---

## Bug 4 — Recursive tunnel loop (CGNAT overlay advertised)

**File:** `cmd/scale-client/setup.go` — `getLocalIPs()`  
**Status:** DONE

Skip `100.64.0.0/10` addresses so `wg0` overlay IPs are not advertised as physical candidates.

---

## Bug 1 — Missing `IpcSet` in HealthMonitor recovery

**File:** `cmd/scale-client/setup.go` — `HealthMonitor()`  
**Status:** DONE

Recovery branch (`!isDead && usingRelay`) now iterates `endpointCache` and `WgDevice.IpcSet`s each peer back to its cached UDP endpoint. `usingRelay = false` only after a successful IpcSet (or empty cache).

---

## Bug 5 — Poll overwrites SmartTrust endpoint

**File:** `cmd/scale-client/setup.go` — `UpdatePeerEndpoint` + `performPollCycle()`  
**Status:** DONE

`UpdatePeerEndpoint` already stored the roamed IP in `endpointCache` and IpcSet WireGuard. Poll was still overwriting that cache with the server LAN candidate every 30s.

`performPollCycle` now prefers a non-empty `endpointCache` entry over server LAN/srflx selection. Server candidate is stored only when the cache is empty. Relay vs UDP uses `IsPeerUdpDead(hexPeerKey)`.

---

## Bug 7 — STUN race / Trickle ICE

**File:** `cmd/scale-client/setup.go` — `main()`, `performPollCycle()`, new `trickleSTUN()`  
**Status:** DONE

Poll no longer blocks on STUN. Local host candidates are heartbeated immediately. `trickleSTUN()` runs STUN in a goroutine (single in-flight) and, on success, caches the srflx endpoint and sends a second heartbeat. Also fired once at startup after `RunControlLoop` starts.

---

## Verification

```
go build ./internal/vpn/
go build -o /tmp/scale-client-v2 ./cmd/scale-client/
```

Both succeeded.
