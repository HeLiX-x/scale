# Scale VPN — v2 Fix Report
> Comprehensive bug report and implementation plan (Updated: 2026-08-27)

---

## Context
During remote WAN testing (Laptop 1 on home WiFi, Laptop 2 on Jio mobile hotspot), a chain of interdependent bugs caused severe route flapping (~26–34s cycle) and data-plane stalls. Fixes were attempted live, then reverted (`commit 23065f4`) to preserve baseline demo integrity. 

This document defines the complete v2 fix plan, aligning the full investigation from `healthmonitor_bugchain_v2.md` with the current codebase state.

---

## Complete Bug & Fix Summary

| Bug # | Bug / Item | Root Cause | Target File & Function | Current Status in Code |
|:---:|---|---|---|:---:|
| **1** | **Flap on Recovery: Missing `IpcSet`** | `HealthMonitor()` toggles `usingRelay=false` but never sends `IpcSet` to WireGuard to restore UDP endpoints. Traffic stays on relay until the 30s poll cycle runs `replace_peers=true`. | `cmd/scale-client/setup.go`<br>`HealthMonitor()` | **FIXED**<br>(Lines 783–804) |
| **2** | **False Reset in `Send()`** | `Send()` resets `udpFailCount = 0` upon local OS socket write buffer success, masking remote UDP delivery failures. | `internal/vpn/hybrid.go`<br>`Send()` | **FIXED**<br>(Lines 224–244) |
| **3** | **KeepAlive Bound to Stale LAN IP** | `StartKeepAlives()` captures initial `*net.UDPAddr` and pings it forever, ignoring roamed addresses learned in `IpMap`. | `internal/vpn/hybrid.go`<br>`StartKeepAlives()` | **FIXED**<br>(Lines 414–464) |
| **4** | **Recursive Tunnel Loop (Overlay IP Advertised)** | `getLocalIPs()` advertises `100.64.x.x` (`wg0` CGNAT overlay) as a physical candidate endpoint, routing probes back into WireGuard relay. | `cmd/scale-client/setup.go`<br>`getLocalIPs()` | **FIXED**<br>(Lines 698–701) |
| **5** | **Poll Overwrites SmartTrust Endpoint** | 30s poll cycle prefers server LAN candidates (`192.168.x`/`10.x`) and blindly overwrites WireGuard endpoints via `replace_peers=true`, clobbering SmartTrust dynamically learned endpoints. | `cmd/scale-client/setup.go`<br>`UpdatePeerEndpoint` & `performPollCycle()` | **FIXED**<br>(Lines 164–181, 348–364) |
| **6** | **Global Health Counters (Not Per-Peer)** | `lastPongTime` and `udpFailCount` are scalar fields on `HybridBind`. Pongs from Peer A reset failure counters for Peer B. | `internal/vpn/hybrid.go`<br>`HybridBind` struct & methods | **FIXED**<br>(Lines 24–63, 397–412) |
| **7** | **STUN Race Condition (Trickle ICE)** | Heartbeat sends candidate endpoints before STUN resolution completes, leaving peer with only unreachable private IPs. | `cmd/scale-client/setup.go`<br>`trickleSTUN()` / `performPollCycle()` | **FIXED**<br>(Lines 273–275, 483–511) |
| **8** | **Premature Recovery (Missing Hysteresis)** | Single transient pong immediately clears dead state. Hysteresis (`udpSuccessCount >= 3`) is needed when transitioning from dead to alive. | `internal/vpn/hybrid.go`<br>`RunControlLoop()` | **FIXED**<br>(Lines 124–136) |

---

## Detailed Bug Analysis & Fixes

---

### Bug 1 — Missing `IpcSet` in Recovery Branch
* **File:** `cmd/scale-client/setup.go`
* **Function:** `HealthMonitor()` (Lines 687–738)
* **Status in Code:** **NOT FIXED** (Post-revert code only logs and sets `usingRelay = false` at lines 729–732 without updating WireGuard).

#### Problem:
When UDP connectivity recovers (`!isDead && usingRelay`), `HealthMonitor()` logs recovery and sets `usingRelay = false`. However, it **never sends an IPC command to WireGuard** to switch peer endpoints back to their direct UDP addresses from `endpointCache`. 

Because WireGuard is still pointing to the WebSocket relay, data traffic stays on relay until the 30-second `performPollCycle` runs `replace_peers=true`. This created the ~26–34s mathematical oscillation seen during testing.

#### Fix:
Update the recovery branch in `HealthMonitor()` to iterate `endpointCache` and push direct UDP endpoints to `WgDevice.IpcSet()`:

```go
} else if !isDead && usingRelay {
    log.Printf("udp recovered, switching back to direct connection")
    var ipcBuilder strings.Builder
    endpointCache.Range(func(key, value interface{}) bool {
        peerHexKey := key.(string)
        udpEndpoint := value.(string) // IP:Port
        ipcBuilder.WriteString(fmt.Sprintf("public_key=%s\n", peerHexKey))
        ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", udpEndpoint))
        return true
    })

    if ipcBuilder.Len() > 0 {
        if err := WgDevice.IpcSet(ipcBuilder.String()); err != nil {
            log.Printf("failed to switch back to direct: %v", err)
        } else {
            usingRelay = false
            log.Println("switched back to direct UDP connection")
        }
    } else {
        usingRelay = false
    }
}
```

---

### Bug 2 — False Reset in `Send()`
* **File:** `internal/vpn/hybrid.go`
* **Function:** `Send()` (Lines 210–230)
* **Status in Code:** **NOT FIXED** (`udpFailCount = 0` still present at lines 226–228).

#### Problem:
In `Send()`, `b.udpFailCount` was set to `0` whenever `b.udpConn.WriteToUDP()` succeeded. Writing to a local OS UDP buffer only confirms that the OS accepted the packet, not that the remote host received it. Because WireGuard retries handshakes every 5 seconds, local write successes were continuously resetting `udpFailCount`, preventing the 15-second dead-peer detection in `StartKeepAlives()` from triggering.

#### Fix:
Delete lines 226–228 in `internal/vpn/hybrid.go`. Fail counters must only be reset by verified incoming pong probes inside `RunControlLoop()`.

```diff
 		if len(errs) > 0 {
 			b.failLock.Lock()
 			b.udpFailCount += len(errs)
 			b.failLock.Unlock()
 			return fmt.Errorf("udp send had %d faliures : %v", len(errs), errs[0])
 		}
-		b.failLock.Lock()
-		b.udpFailCount = 0
-		b.failLock.Unlock()
 		return nil
```

---

### Bug 3 — `StartKeepAlives()` Locked to Stale Initial IP
* **File:** `internal/vpn/hybrid.go` & `cmd/scale-client/setup.go`
* **Function:** `HybridBind.StartKeepAlives()` (`hybrid.go:374–410`) and caller in `performPollCycle()` (`setup.go:359–367`)
* **Status in Code:** **NOT FIXED** (Signature only takes `peerAddr *net.UDPAddr` and sends to it statically).

#### Problem:
`StartKeepAlives()` is initialized with an initial `*net.UDPAddr` (typically the LAN IP). When `RunControlLoop()` detects a roamed public IP from hole punching and updates `b.IpMap[peerKey]`, `StartKeepAlives()` never checks `IpMap`. It continues sending keepalive probes to the dead LAN IP, causing a false timeout declaration every 15 seconds.

#### Fix:
Change `StartKeepAlives` to take `peerKeyHex string` and `initialAddr *net.UDPAddr`. Perform a dynamic lookup in `b.IpMap` on each tick:

```go
func (b *HybridBind) StartKeepAlives(ctx context.Context, peerKeyHex string, initialAddr *net.UDPAddr) {
    ticker := time.NewTicker(time.Second * 5)
    defer ticker.Stop()

    probePkt := make([]byte, 36)
    binary.BigEndian.PutUint32(probePkt[0:4], MagicProbeSig)
    copy(probePkt[4:], b.myPubKey[:])

    b.pongLock.Lock()
    b.lastPongTime = time.Now()
    b.pongLock.Unlock()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            b.mapLock.Lock()
            currentAddr, ok := b.IpMap[peerKeyHex]
            b.mapLock.Unlock()
            if !ok || currentAddr == nil {
                currentAddr = initialAddr
            }

            err := b.SendRaw(probePkt, currentAddr)
            if err != nil {
                log.Printf("failed to send keepalives to %s: %v", currentAddr.String(), err)
                continue
            }

            b.pongLock.Lock()
            lastPong := b.lastPongTime
            b.pongLock.Unlock()

            if !lastPong.IsZero() && time.Since(lastPong) > 15*time.Second {
                log.Printf("udp peer %s is dead (last pong > 15s, endpoint: %s)", peerKeyHex[:8], currentAddr.String())
                b.failLock.Lock()
                b.udpFailCount = 5
                b.failLock.Unlock()
            }
        }
    }
}
```

---

### Bug 4 — Recursive Tunnel Loop (`100.64.0.0/10` CGNAT Overlay Advertised)
* **File:** `cmd/scale-client/setup.go`
* **Function:** `getLocalIPs()` (Lines 623–665)
* **Status in Code:** **NOT FIXED** (No CIDR exclusion in current `getLocalIPs()`).

#### Problem:
`getLocalIPs()` enumerates all non-loopback IPv4 interface addresses. Once `wg0` comes up with its `100.64.x.x` overlay IP, `getLocalIPs()` advertises `100.64.x.x` to the control server as a physical endpoint. Peers probe `100.64.x.x`, which routes back into `wg0` and over the relay, falsely registering as a healthy direct UDP pong.

#### Fix:
Filter out `100.64.0.0/10` CGNAT overlay addresses in `getLocalIPs()`:

```go
_, cgnatPrefix, _ := net.ParseCIDR("100.64.0.0/10")
for _, i := range ifaces {
    addrs, _ := i.Addrs()
    for _, addr := range addrs {
        var ip net.IP
        switch v := addr.(type) {
        case *net.IPNet:
            ip = v.IP
        case *net.IPAddr:
            ip = v.IP
        }

        if ip == nil || !ip.IsPrivate() && !ip.IsGlobalUnicast() {
            // standard validations
        }
        if ip.To4() == nil || ip.IsLoopback() {
            continue
        }

        // Exclude VPN overlay subnet
        if cgnatPrefix.Contains(ip) {
            log.Printf("Skipping VPN overlay IP: %s", ip.String())
            continue
        }

        endpoints = append(endpoints, Endpoint{
            IP:       ip.String(),
            Port:     listenPort,
            Protocol: "udp",
            Type:     "host",
        })
    }
}
```

---

### Bug 5 — Poll Cycle Overwrites SmartTrust Endpoint & Incomplete Cache Sync
* **File:** `cmd/scale-client/setup.go`
* **Functions:** `bind.UpdatePeerEndpoint` callback (Lines 157–174) & `performPollCycle()` (Lines 263–382)
* **Status in Code:** **NOT FIXED** (`performPollCycle` blindly picks server LAN endpoints and resets `endpointCache` and WireGuard, while cache population during initial poll locks to LAN candidate).

#### Problem:
This is why the 4-fix live build had a dead data plane despite probe pongs succeeding:
1. On startup / first poll, `performPollCycle()` stores the server-provided LAN IP (`192.168.x` / `10.x`) into `endpointCache`.
2. Hole punch succeeds across WAN, and `SmartTrust` (`bind.UpdatePeerEndpoint`) learns the actual roamed public IP.
3. If `performPollCycle()` simply prefers `endpointCache` without proper synchronization, two issues occur:
   - If `UpdatePeerEndpoint` doesn't reliably update `endpointCache`, `performPollCycle` forever retains the initial stale LAN IP from the first poll.
   - Every 30 seconds, `performPollCycle()` runs `replace_peers=true` with the server's LAN candidate, clobbering the live SmartTrust endpoint on WireGuard.

#### Fix (Two-Way Synchronization):
1. **In `bind.UpdatePeerEndpoint` (`setup.go`):** Ensure the dynamically learned address is stored into `endpointCache` and pushed to WireGuard via `IpcSet`:
```go
bind.UpdatePeerEndpoint = func(peerKey string, newAddr *net.UDPAddr) {
    if last, loaded := endpointCache.Load(peerKey); loaded {
        if last.(string) == newAddr.String() {
            return
        }
    }
    // Update cache with dynamic roamed endpoint
    endpointCache.Store(peerKey, newAddr.String())

    go func() {
        cfg := fmt.Sprintf("public_key=%s\nendpoint=%s\n", peerKey, newAddr.String())
        if err := WgDevice.IpcSet(cfg); err != nil {
            log.Printf("Smart Trust: failed to set endpoint for %s: %v", peerKey[:8], err)
        } else {
            log.Printf("Smart Trust: Peer %s moved to %s", peerKey[:8], newAddr.String())
        }
    }()
}
```

2. **In `performPollCycle` (`setup.go`):** Prefer the cached endpoint if present (which contains the SmartTrust roamed address). Only fall back to server candidates if `endpointCache` has no entry:
```go
// In performPollCycle endpoint selection:
var finalEndpointStr string
if cachedEp, ok := endpointCache.Load(hexPeerKey); ok && cachedEp.(string) != "" {
    finalEndpointStr = cachedEp.(string)
} else if found {
    finalEndpointStr = fmt.Sprintf("%s:%d", bestEndpoint.IP, bestEndpoint.Port)
    endpointCache.Store(hexPeerKey, finalEndpointStr)
}

if finalEndpointStr != "" {
    if bind.IsPeerUdpDead(hexPeerKey) {
        ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", hexPeerKey))
        log.Printf("🔹 PEER CONNECT (RELAY): %s -> %s", peer.PublicKey[:8], hexPeerKey)
    } else {
        ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", finalEndpointStr))
        log.Printf("🔹 PEER CONNECT (UDP): %s -> %s", peer.PublicKey[:8], finalEndpointStr)
    }
}
```

---

### Bug 6 & 8 — Per-Peer Health Tracking & State-Gated Recovery Hysteresis
* **File:** `internal/vpn/hybrid.go`
* **Components:** `HybridBind` struct (Lines 24–45), `RunControlLoop()` (Lines 99–144), `IsPeerUdpDead()`, `StartKeepAlives()`
* **Status in Code:** **NOT FIXED** (`lastPongTime` and `udpFailCount` are global scalar fields; no `successCounts` map; probe verification resets fail count unconditionally).

#### Problem:
1. **Multi-peer cross-talk:** Global `udpFailCount` and `lastPongTime` cause pongs from Peer A to mask dead connections to Peer B.
2. **Flapping on lossy links:** Without hysteresis, a single lucky probe on a 90% lossy link instantly clears dead state, causing `HealthMonitor` to switch back to direct UDP prematurely.
3. **Architecture note:** Implementing hysteresis on scalar counters first is wasteful because it gets immediately rewritten for per-peer tracking. Per-peer maps must be the foundation.

#### Fix:
1. **Define per-peer maps in `HybridBind` struct:**
```go
type HybridBind struct {
    // ...
    failCounts    map[string]int
    failLock      sync.Mutex

    lastPongs     map[string]time.Time
    pongLock      sync.Mutex

    successCounts map[string]int
    // ...
}

func (b *HybridBind) IsPeerUdpDead(peerKeyHex string) bool {
    b.failLock.Lock()
    defer b.failLock.Unlock()
    return b.failCounts[peerKeyHex] >= threshold
}
```

2. **Apply hysteresis directly to `failCounts[peerKey]` in `RunControlLoop`:**
```go
// Inside RunControlLoop upon receiving valid probe for peerKey:
b.pongLock.Lock()
b.lastPongs[peerKey] = time.Now()
b.pongLock.Unlock()

b.failLock.Lock()
if b.failCounts[peerKey] >= threshold {
    // Currently dead: require 3 consecutive pongs before declaring recovered
    b.successCounts[peerKey]++
    if b.successCounts[peerKey] >= 3 {
        b.failCounts[peerKey] = 0
        b.successCounts[peerKey] = 0
        log.Printf("Peer %s: 3 consecutive pongs received, direct UDP path recovered", peerKey[:8])
    }
} else {
    // Already healthy: maintain 0 failures
    b.failCounts[peerKey] = 0
    b.successCounts[peerKey] = 0
}
b.failLock.Unlock()
```

---

### Feature / Fix 7 — STUN Trickle ICE (Candidate Race Condition)
* **File:** `cmd/scale-client/setup.go`
* **Functions:** `main()` (Lines 134–140), `performPollCycle()` (Lines 263–268), `updateHeartbeat()` (Lines 502–540)
* **Status in Code:** **NOT FIXED** (STUN is invoked synchronously during polling).

#### Problem:
`getLocalIPs()` completes in microseconds, whereas STUN requests take 150–750ms. If candidate endpoints are registered before STUN finishes, remote peers only receive LAN addresses.

#### Fix:
1. Immediately register/heartbeat with local physical candidate IPs.
2. Resolve STUN asynchronously in a goroutine.
3. When STUN resolves, immediately trigger a second heartbeat with the public candidate appended.

```go
// Asynchronous STUN candidate update
go func() {
    srflxEp, err := performSTUN(bind, "stun.l.google.com:19302")
    if err == nil && srflxEp != nil {
        localEps, _ := getLocalIPs()
        _ = updateHeartbeat(client, serverURL, publicKey, authToken, srflxEp, localEps)
        log.Printf("Trickle ICE: STUN public candidate (%s:%d) sent to server", srflxEp.IP, srflxEp.Port)
    }
}()
```

---

### Architectural Context — Symmetric NAT Awareness
**Behavioral / Protocol Note:**
Indian mobile carriers (Jio, Airtel, Vi) almost universally run Symmetric NAT + CGNAT. Under Symmetric NAT, STUN can successfully return a public IP, but that IP:port mapping is only valid for the specific connection used to test it. When WireGuard tries to use that mapping for a handshake with a different peer, the NAT creates a new random port. The handshake never lands.

For symmetric NAT peers, direct P2P is **structurally impossible**. The WebSocket relay fallback is not a bug workaround — it is the correct, intended behavior.

---

## Files To Touch Summary

| File | Target Function | Lines | Required Action | Status |
|---|---|---|---|:---:|
| [`internal/vpn/hybrid.go`](file:///home/sankalp/Documents/scale/internal/vpn/hybrid.go) | `HybridBind` struct | 24–45 | Replace global scalars with per-peer maps (`failCounts`, `lastPongs`, `successCounts`) | **FIXED** |
| [`internal/vpn/hybrid.go`](file:///home/sankalp/Documents/scale/internal/vpn/hybrid.go) | `Send()` | 224–244 | Remove false `udpFailCount = 0` reset on OS socket buffer write | **FIXED** |
| [`internal/vpn/hybrid.go`](file:///home/sankalp/Documents/scale/internal/vpn/hybrid.go) | `StartKeepAlives()` | 414–464 | Dynamic `IpMap[peerKey]` lookup per tick & per-peer dead marking | **FIXED** |
| [`internal/vpn/hybrid.go`](file:///home/sankalp/Documents/scale/internal/vpn/hybrid.go) | `RunControlLoop()` | 124–136 | Implement per-peer hysteresis (`successCounts[peerKey] >= 3`) when dead | **FIXED** |
| [`cmd/scale-client/setup.go`](file:///home/sankalp/Documents/scale/cmd/scale-client/setup.go) | `getLocalIPs()` | 698–701 | Add `100.64.0.0/10` CGNAT CIDR filter to prevent tunnel recursion | **FIXED** |
| [`cmd/scale-client/setup.go`](file:///home/sankalp/Documents/scale/cmd/scale-client/setup.go) | `HealthMonitor()` | 783–804 | Add `WgDevice.IpcSet` on recovery to restore direct UDP endpoints from `endpointCache` | **FIXED** |
| [`cmd/scale-client/setup.go`](file:///home/sankalp/Documents/scale/cmd/scale-client/setup.go) | `UpdatePeerEndpoint` & `performPollCycle()` | 164–181, 348–364 | Synchronize `endpointCache` with SmartTrust and prefer cached roamed IP in poll | **FIXED** |
| [`cmd/scale-client/setup.go`](file:///home/sankalp/Documents/scale/cmd/scale-client/setup.go) | `performPollCycle()` / `trickleSTUN()` | 273–275, 483–511 | Implement Trickle ICE (async STUN candidate push) | **FIXED** |

---

## Correct Implementation Order of Operations (Dependency-Ordered)

```
1. Core Engine Foundation (internal/vpn/hybrid.go)
   ├── Step 1.1: Migrate HybridBind struct to per-peer maps (failCounts, lastPongs, successCounts map[string]int/time.Time)
   ├── Step 1.2: Delete false reset (udpFailCount = 0) in Send()
   ├── Step 1.3: Update StartKeepAlives(ctx, peerKeyHex, initialAddr) with dynamic per-tick IpMap lookups
   └── Step 1.4: Implement per-peer recovery hysteresis (successCounts[peerKey] >= 3 only when dead) in RunControlLoop()

2. Client Orchestrator & WireGuard Integration (cmd/scale-client/setup.go)
   ├── Step 2.1: Add 100.64.0.0/10 CGNAT CIDR filter to getLocalIPs()
   ├── Step 2.2: Add WgDevice.IpcSet to HealthMonitor() recovery branch
   ├── Step 2.3: Implement two-way SmartTrust cache sync (UpdatePeerEndpoint stores roamed IP; performPollCycle prefers endpointCache)
   └── Step 2.4: Wire async STUN Trickle ICE in startup/heartbeat

3. Local and Cross-Network Verification
   ├── Step 3.1: Build and unit-check two clients on localhost / same machine
   ├── Step 3.2: LAN verification (two machines on same WiFi subnet)
   └── Step 3.3: WAN verification (Home WiFi laptop + Jio Hotspot laptop via AWS Relay)
```

