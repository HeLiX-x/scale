package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"scale/internal/vpn"

	"github.com/joho/godotenv"
	"github.com/pion/stun/v2"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	pollInterval      = 30 * time.Second
	keepAliveInterval = 25
)

var WgDevice *device.Device

var endpointCache sync.Map

var activeSprayers sync.Map

// activeKeepAlives tracks the cancel func for each peer's running
// StartKeepAlives loop, keyed by hex peer key, so we don't spawn a
// duplicate loop on every poll cycle and so we can stop it when the
// peer disappears or the client shuts down.
var activeKeepAlives sync.Map

var (
	cachedSrflx     *Endpoint
	cachedSrflxLock sync.Mutex
	stunMu          sync.Mutex
	stunRunning     bool
)

type Endpoint struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
}

type PeerInfo struct {
	ID         string     `json:"id"`
	PublicKey  string     `json:"public_key"`
	Endpoints  []Endpoint `json:"endpoints,omitempty"`
	AllowedIPs []string   `json:"allowed_ips"`
}

type PeerConfig struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

type PollResponse struct {
	Peers []PeerInfo `json:"peers"`
}

type RegistrationConfig struct {
	AssignedIP string `json:"assigned_ip"`
}

var listenPort = 51820

var (
	vpnCtx      context.Context
	vpnCancel   context.CancelFunc
	snapshotMu  sync.RWMutex
	snapshot    RuntimeSnapshot
	lastPeers   []PeerInfo
	usingRelay  atomic.Bool
	controlOK   atomic.Bool
	overlayIP   string
	pubKeyStr   string
	controlURL  string
	relayURLStr string
	ifaceName   string
)

func cmdUp(_ []string) error {
	if err := requireRoot("up"); err != nil {
		return err
	}
	if pid, ok := runningPID(); ok {
		return fmt.Errorf("Scale VPN is already running (pid %d)", pid)
	}

	ctx, cancel := context.WithCancel(context.Background())
	vpnCtx = ctx
	vpnCancel = cancel
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	return runVPN(ctx)
}

func runVPN(ctx context.Context) error {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found, using environment variables.")
	}

	log.Println("🔍 DEBUG: Testing IP Detection immediately...")
	if _, err := getLocalIPs(); err != nil {
		log.Printf("Error getting IPs: %v", err)
	}

	cfg := loadConfig()
	wgIface := firstNonEmpty(os.Getenv("WG_INTERFACE"), cfg.Interface, "wg0")
	ifaceName = wgIface

	if envPort := os.Getenv("WG_PORT"); envPort != "" {
		var err error
		listenPort, err = strconv.Atoi(envPort)
		if err != nil {
			return fmt.Errorf("invalid WG_PORT: %w", err)
		}
	} else if cfg.Port > 0 {
		listenPort = cfg.Port
	}
	log.Printf("Starting WireGuard on %s : %d", wgIface, listenPort)

	serverURL := strings.TrimSuffix(firstNonEmpty(cfg.ControlServer, os.Getenv("WG_CONTROL_SERVER")), "/")
	authToken := firstNonEmpty(readToken(), strings.TrimSpace(os.Getenv("AUTH_TOKEN")))
	relayURL := firstNonEmpty(cfg.RelayURL, os.Getenv("RELAY_URL"))
	controlURL = serverURL
	relayURLStr = relayURL

	if authToken == "" {
		return fmt.Errorf("Please run 'scale login' first")
	}
	if serverURL == "" || relayURL == "" {
		return fmt.Errorf("control server and relay URL must be set (run 'scale login --server ... --relay ...')")
	}

	privKey, pubKey, err := generateOrLoadKeys()
	if err != nil {
		return fmt.Errorf("key setup failed: %w", err)
	}
	pubKeyStr = pubKey.String()

	log.Println("Registering with control server...")
	regConfig, err := registerDeviceAndGetIP(serverURL, pubKey.String(), authToken)
	if err != nil {
		return fmt.Errorf("failed to register device: %w", err)
	}
	log.Printf("Successfully registered. Assigned IP: %s", regConfig.AssignedIP)
	overlayIP = regConfig.AssignedIP

	log.Println("⚡ Starting Userspace WireGuard Engine (Hybrid Mode)...")

	tunDev, err := tun.CreateTUN(wgIface, 1420)
	if err != nil {
		_ = exec.Command("ip", "link", "delete", wgIface).Run()
		tunDev, err = tun.CreateTUN(wgIface, 1420)
		if err != nil {
			return fmt.Errorf("failed to create TUN device: %w", err)
		}
	}

	bind, err := vpn.NewHybridBind(listenPort, relayURL, hexKey(pubKey))
	if err != nil {
		return fmt.Errorf("failed to create HybridBind: %w", err)
	}

	bind.UpdatePeerEndpoint = func(peerKey string, newAddr *net.UDPAddr) {
		if last, loaded := endpointCache.Load(peerKey); loaded {
			if last.(string) == newAddr.String() {
				return
			}
		}

		endpointCache.Store(peerKey, newAddr.String())

		go func() {
			ipcCfg := fmt.Sprintf("public_key=%s\nendpoint=%s\n", peerKey, newAddr.String())
			if err := WgDevice.IpcSet(ipcCfg); err != nil {
				endpointCache.Delete(peerKey)
			} else {
				log.Printf("Smart Trust: Peer %s moved to %s", peerKey[:8], newAddr.String())
			}
		}()
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("[%s] ", wgIface))
	WgDevice = device.NewDevice(tunDev, bind, logger)
	WgDevice.Up()

	if err := ForceConfigureInterface(wgIface, regConfig.AssignedIP); err != nil {
		log.Printf("Warning: Manual IP setup failed: %v", err)
	}

	conf := fmt.Sprintf(`private_key=%s
`, hexKey(privKey))

	log.Println("Applying WireGuard configuration (private key only)...")

	done := make(chan error, 1)
	go func() {
		done <- WgDevice.IpcSet(conf)
	}()

	select {
	case err := <-done:
		if err != nil {
			teardownVPN(bind, wgIface)
			return fmt.Errorf("IpcSet failed: %w", err)
		}
		log.Println("applied successfully.")
	case <-time.After(5 * time.Second):
		teardownVPN(bind, wgIface)
		return fmt.Errorf("IpcSet timed out, check hybridbind implementation")
	}

	if err := writePID(); err != nil {
		log.Printf("Warning: failed to write pid file: %v", err)
	}
	if err := startIPC(vpnCancel); err != nil {
		log.Printf("Warning: status socket unavailable: %v", err)
	}
	publishSnapshot(bind)

	log.Println("Client running. Starting polling loop...")

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		bind.RunControlLoop()
	}()
	go func() {
		defer wg.Done()
		runServerPollingLoop(ctx, bind, serverURL, pubKey.String(), authToken)
	}()
	go func() {
		defer wg.Done()
		HealthMonitor(ctx, bind)
	}()

	trickleSTUN(bind, &http.Client{Timeout: 10 * time.Second}, serverURL, pubKey.String(), authToken)

	<-ctx.Done()
	log.Println("Shutdown signal received.")
	teardownVPN(bind, wgIface)
	wg.Wait()
	fmt.Println("Scale VPN disconnected. Network interface wg0 removed.")
	return nil
}

func runServerPollingLoop(ctx context.Context, bind *vpn.HybridBind, serverURL, publicKey, authToken string) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	httpClient := &http.Client{Timeout: 10 * time.Second}

	performPollCycle(bind, httpClient, serverURL, publicKey, authToken)

	for {
		select {
		case <-ticker.C:
			performPollCycle(bind, httpClient, serverURL, publicKey, authToken)
		case <-ctx.Done():
			log.Println("Gracefully stopping polling loop...")
			return
		}
	}
}

func performPollCycle(bind *vpn.HybridBind, client *http.Client, serverURL, publicKey, authToken string) {
	localEps, _ := getLocalIPs()
	updateHeartbeat(client, serverURL, publicKey, authToken, getCachedSrflx(), localEps)
	trickleSTUN(bind, client, serverURL, publicKey, authToken)

	pollResp, err := pollServer(client, serverURL, authToken, publicKey)
	if err != nil || pollResp == nil {
		controlOK.Store(false)
		publishSnapshot(bind)
		return
	}
	controlOK.Store(true)
	snapshotMu.Lock()
	lastPeers = pollResp.Peers
	snapshotMu.Unlock()

	// Convert YOUR key once
	selfKeyBytes, _ := wgtypes.ParseKey(publicKey)
	hexSelfKey := hex.EncodeToString(selfKeyBytes[:])

	var ipcBuilder strings.Builder
	// MANDATORY: Clear old state and start fresh
	ipcBuilder.WriteString("replace_peers=true\n")
	seenPeers := make(map[string]bool)

	for _, peer := range pollResp.Peers {
		if peer.PublicKey == publicKey {
			continue
		}

		// 2. HEX CONVERSION
		peerKeyBytes, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			log.Printf(" Invalid key %s, skipping", peer.PublicKey[:8])
			continue
		}
		hexPeerKey := hex.EncodeToString(peerKeyBytes[:])
		seenPeers[hexPeerKey] = true

		// 3. IP VALIDATION (The actual fix for Error -22)
		// Strip any existing mask from peer.ID (e.g., "100.64.0.7/24" -> "100.64.0.7")
		cleanIP := strings.Split(peer.ID, "/")[0]
		parsedIP := net.ParseIP(cleanIP)
		if parsedIP == nil {
			log.Printf(" Peer %s has invalid IP '%s', skipping", peer.PublicKey[:8], peer.ID)
			continue
		}

		// 4. ENDPOINT SELECTION
		var bestEndpoint Endpoint
		found := false
		for _, ep := range peer.Endpoints {
			if strings.HasPrefix(ep.IP, "192.168.") || strings.HasPrefix(ep.IP, "10.") {
				bestEndpoint = ep
				found = true
				break
			}
		}
		// BUG FIX: prefer the STUN-derived public (srflx) endpoint over a
		// blind index-0 fallback. Without this, a peer's host-enumerated
		// addresses (e.g. a docker bridge or secondary NIC IP, whatever
		// happened to be first in the list) could get picked over its
		// actual reachable public address - fine on a shared LAN where
		// almost anything routes, but silently wrong once the peer is on
		// a different network and only the srflx address is reachable.
		if !found {
			for _, ep := range peer.Endpoints {
				if ep.Type == "srflx" {
					bestEndpoint = ep
					found = true
					break
				}
			}
		}
		if !found && len(peer.Endpoints) > 0 {
			bestEndpoint = peer.Endpoints[0]
			found = true
		}

		// 5. BUILD PEER BLOCK (Atomic String Construction)
		ipcBuilder.WriteString("public_key=" + hexPeerKey + "\n")
		ipcBuilder.WriteString("allowed_ip=" + cleanIP + "/32\n")
		ipcBuilder.WriteString("persistent_keepalive_interval=25\n")

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

			if udpAddr, err := net.ResolveUDPAddr("udp", finalEndpointStr); err == nil {
				parent := vpnCtx
				if parent == nil {
					parent = context.Background()
				}
				child, cancel := context.WithCancel(parent)
				if _, alreadyRunning := activeKeepAlives.LoadOrStore(hexPeerKey, cancel); alreadyRunning {
					cancel()
				} else {
					go bind.StartKeepAlives(child, hexPeerKey, udpAddr)
				}
			} else {
				log.Printf("could not resolve endpoint for keepalive, peer %s: %v", peer.PublicKey[:8], err)
			}
		}

		// 6. HOLE PUNCHING
		StartHolePunching(bind, hexPeerKey, peer.Endpoints, hexSelfKey)
	}

	activeKeepAlives.Range(func(k, v interface{}) bool {
		key := k.(string)
		if !seenPeers[key] {
			if cancel, ok := v.(context.CancelFunc); ok {
				cancel()
			}
			activeKeepAlives.Delete(key)
		}
		return true
	})

	// 7. APPLY EVERYTHING AT ONCE
	if ipcBuilder.Len() > 0 {
		configBlob := ipcBuilder.String()
		if err := WgDevice.IpcSet(configBlob); err != nil {
			log.Printf("❌ IPC Error. Full config attempted:\n%s", configBlob)
			log.Printf("❌ Detailed Error: %v", err)
		}
	}
	publishSnapshot(bind)
}

func pollServer(client *http.Client, serverURL, authToken, clientPubKey string) (*PollResponse, error) {
	req, err := http.NewRequest("GET", serverURL+"/api/poll", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Device-Public-Key", clientPubKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %s", resp.Status)
	}

	var pollResp PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		return nil, err
	}
	return &pollResp, nil
}

func registerDeviceAndGetIP(serverURL, publicKey, authToken string) (*RegistrationConfig, error) {
	payload, _ := json.Marshal(map[string]interface{}{"public_key": publicKey})
	req, err := http.NewRequest("POST", serverURL+"/api/devices/register", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %s", resp.Status)
	}
	var config RegistrationConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func generateOrLoadKeys() (wgtypes.Key, wgtypes.Key, error) {
	if err := ensureScaleDir(); err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, err
	}
	path := keyPath()

	if data, err := os.ReadFile(path); err == nil {
		keyStr := strings.TrimSpace(string(data))
		if k, err := wgtypes.ParseKey(keyStr); err == nil {
			return k, k.PublicKey(), nil
		}
	}

	key, err := wgtypes.GenerateKey()
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, err
	}

	if err := writeSecureFile(path, []byte(key.String()), 0600); err != nil {
		log.Printf("Warning: failed to save key to disk: %v", err)
	}

	return key, key.PublicKey(), nil
}

func hexKey(k wgtypes.Key) string {
	return hex.EncodeToString(k[:])
}

func teardownVPN(bind *vpn.HybridBind, iface string) {
	activeKeepAlives.Range(func(k, v interface{}) bool {
		if cancel, ok := v.(context.CancelFunc); ok {
			cancel()
		}
		activeKeepAlives.Delete(k)
		return true
	})
	if WgDevice != nil {
		WgDevice.Close()
		WgDevice = nil
	}
	if bind != nil {
		bind.Shutdown()
	}
	_ = exec.Command("ip", "link", "delete", iface).Run()
	removePID()
	_ = os.Remove(socketPath())
	_ = os.Remove(statusPath())
	time.Sleep(200 * time.Millisecond)
}

func classifyNAT(srflx *Endpoint) string {
	if srflx == nil {
		return "Unknown"
	}
	if srflx.Port == listenPort {
		return "Easy / Port-Preserving"
	}
	return "Restricted / Symmetric"
}

func peerStatus(last time.Time, relay bool) string {
	if last.IsZero() {
		return "OFFLINE"
	}
	age := time.Since(last)
	if age <= 10*time.Second {
		if relay {
			return "HEALTHY (Relay)"
		}
		return "HEALTHY"
	}
	if age <= 20*time.Second {
		return "DEGRADED"
	}
	return "OFFLINE"
}

func publishSnapshot(bind *vpn.HybridBind) {
	if bind == nil {
		return
	}
	snapshotMu.RLock()
	peersSrc := append([]PeerInfo(nil), lastPeers...)
	snapshotMu.RUnlock()
	pongs := bind.SnapshotPongs()
	relay := usingRelay.Load() || bind.IsUdpDead()
	peers := make([]PeerSnap, 0, len(peersSrc))
	online := 0
	for _, peer := range peersSrc {
		if peer.PublicKey == pubKeyStr {
			continue
		}
		peerKeyBytes, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			continue
		}
		hexPeerKey := hex.EncodeToString(peerKeyBytes[:])
		transport := "Direct UDP"
		dead := bind.IsPeerUdpDead(hexPeerKey) || usingRelay.Load()
		if dead {
			transport = "WebSocket Relay"
		}
		last := pongs[hexPeerKey]
		st := peerStatus(last, dead)
		if strings.HasPrefix(st, "HEALTHY") {
			online++
		}
		peers = append(peers, PeerSnap{
			OverlayIP: peer.ID,
			PublicKey: peer.PublicKey,
			Transport: transport,
			LastPong:  last,
			Status:    st,
		})
	}
	nat := "Unknown"
	if srflx := getCachedSrflx(); srflx != nil {
		nat = classifyNAT(srflx)
	}
	snap := RuntimeSnapshot{
		Status:         "CONNECTED",
		Interface:      ifaceName,
		OverlayIP:      overlayIP,
		PublicKey:      pubKeyStr,
		ControlServer:  redactURL(controlURL),
		ControlOK:      controlOK.Load(),
		RelayServer:    redactURL(relayURLStr),
		RelayConnected: bind.RelayConnected(),
		NATType:        nat,
		UsingRelay:     relay,
		ActivePeers:    online,
		Peers:          peers,
	}
	snapshotMu.Lock()
	snapshot = snap
	snapshotMu.Unlock()
	writeSnapshotFile(snap)
}

func getCachedSrflx() *Endpoint {
	cachedSrflxLock.Lock()
	defer cachedSrflxLock.Unlock()
	return cachedSrflx
}

func setCachedSrflx(ep *Endpoint) {
	cachedSrflxLock.Lock()
	defer cachedSrflxLock.Unlock()
	cachedSrflx = ep
}

func trickleSTUN(bind *vpn.HybridBind, client *http.Client, serverURL, publicKey, authToken string) {
	stunMu.Lock()
	if stunRunning {
		stunMu.Unlock()
		return
	}
	stunRunning = true
	stunMu.Unlock()

	go func() {
		defer func() {
			stunMu.Lock()
			stunRunning = false
			stunMu.Unlock()
		}()

		srflxEp, err := performSTUN(bind, "stun.l.google.com:19302")
		if err != nil || srflxEp == nil {
			return
		}
		setCachedSrflx(srflxEp)
		localEps, _ := getLocalIPs()
		if err := updateHeartbeat(client, serverURL, publicKey, authToken, srflxEp, localEps); err != nil {
			log.Printf("Trickle ICE: heartbeat failed: %v", err)
			return
		}
		log.Printf("Trickle ICE: STUN public candidate (%s:%d) sent to server", srflxEp.IP, srflxEp.Port)
	}()
}

func performSTUN(bind *vpn.HybridBind, stunServer string) (*Endpoint, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", stunServer)
	if err != nil {
		return nil, err
	}

	msg := stun.MustBuild(stun.BindingRequest, stun.TransactionID)

	if err := bind.SendRaw(msg.Raw, serverAddr); err != nil {
		return nil, err
	}

	timeout := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-bind.StunRxChan:
			if vpn.VerifyStun(pkt.Data) {
				resp := new(stun.Message)
				resp.Raw = pkt.Data
				if err := resp.Decode(); err == nil {
					var xorAddr stun.XORMappedAddress
					if err := xorAddr.GetFrom(resp); err == nil {
						return &Endpoint{
							IP:       xorAddr.IP.String(),
							Port:     xorAddr.Port,
							Protocol: "udp",
							Type:     "srflx",
						}, nil
					}
				}
			}
		case <-timeout:
			return nil, fmt.Errorf("STUN timeout")
		}
	}
}

func updateHeartbeat(client *http.Client, serverUrl, publicKey, authToken string, srflx *Endpoint, hostEps []Endpoint) error {

	type heartBeatPayload struct {
		SrflxEndpoint *Endpoint  `json:"srflx_endpoint,omitempty"`
		HostEndpoints []Endpoint `json:"host_endpoints"`
	}

	payload := heartBeatPayload{
		SrflxEndpoint: srflx,
		HostEndpoints: hostEps,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", serverUrl+"/api/devices/heartbeat", bytes.NewReader(payloadBytes))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Device-Public-Key", publicKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat failed with error : %s", resp.Status)
	}

	return nil
}

func loginToServer(serverUrl, email, password string) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})

	if err != nil {
		return "", err
	}

	resp, err := http.Post(serverUrl+"/api/login", "application/json", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed with status %s", resp.Status)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	token, ok := result["token"]
	if !ok {
		return "", fmt.Errorf("response does not contain token")
	}
	return token, nil
}

func StartHolePunching(bind *vpn.HybridBind, peerKey string, endpoints []Endpoint, myLocalPubKey string) {

	if _, loaded := activeSprayers.LoadOrStore(peerKey, true); loaded {
		return
	}

	var candidates []*net.UDPAddr
	for _, ep := range endpoints {

		if ep.Protocol == "udp" {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ep.IP, ep.Port))
			if err == nil {
				candidates = append(candidates, addr)
			}
		}
	}

	if len(candidates) == 0 {
		activeSprayers.Delete(peerKey)
		return
	}

	go func() {
		defer activeSprayers.Delete(peerKey)

		pkt := make([]byte, 36)
		binary.BigEndian.PutUint32(pkt[:4], vpn.MagicProbeSig)

		myKeyBytes, err := hex.DecodeString(myLocalPubKey)
		if err != nil || len(myKeyBytes) != 32 {
			log.Printf("Error decoding local key for hole punching: %v", err)
			return
		}
		copy(pkt[4:], myKeyBytes)

		log.Printf("Spraying %d candidates for peer %s...", len(candidates), peerKey[:8])

		for i := 0; i < 5; i++ {
			for _, addr := range candidates {
				if err := bind.SendRaw(pkt, addr); err != nil {
				}
			}
			time.Sleep(150 * time.Millisecond)
		}

	}()
}

func getLocalIPs() ([]Endpoint, error) {
	var endpoints []Endpoint
	_, cgnatPrefix, _ := net.ParseCIDR("100.64.0.0/10")
	ifaces, _ := net.Interfaces()
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

			isLoopback := ip.IsLoopback()
			isIPv4 := (ip.To4() != nil)
			log.Printf("Scanned IP: %s (Loopback: %v, IPv4: %v)", ip.String(), isLoopback, isIPv4)

			if !isIPv4 {
				continue
			}

			if isLoopback {
				continue
			}

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

	if len(endpoints) == 0 {
		log.Println("WARNING: No local endpoints found! Client will be invisible to peers.")
	} else {
		log.Printf("Sending %d local endpoints to server.", len(endpoints))
	}

	return endpoints, nil
}

func ForceConfigureInterface(iface string, ipCIDR string) error {
	log.Printf("Forcing interface configuration via shell...")

	cmdUp := exec.Command("ip", "link", "set", "dev", iface, "up")
	if out, err := cmdUp.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set link up: %v, output: %s", err, out)
	}

	fullIP := ipCIDR
	if !strings.Contains(fullIP, "/") {
		fullIP = fullIP + "/32"
	}

	cmdAddr := exec.Command("ip", "addr", "add", ipCIDR, "dev", iface)
	_ = cmdAddr.Run()

	log.Printf("Interface %s configured with IP %s via shell", iface, ipCIDR)
	return nil
}

func HealthMonitor(ctx context.Context, b *vpn.HybridBind) {
	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			isDead := b.IsUdpDead()

			if isDead && !usingRelay.Load() {
				log.Printf("udp failed! shifting to relay")

				var ipcBuilder strings.Builder

				endpointCache.Range(func(key, value interface{}) bool {
					peerHexKey := key.(string)

					ipcBuilder.WriteString(fmt.Sprintf("public_key=%s\n", peerHexKey))
					ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", peerHexKey))

					return true
				})

				if ipcBuilder.Len() > 0 {
					if err := WgDevice.IpcSet(ipcBuilder.String()); err != nil {
						log.Printf("failed to switch to relay: %v", err)
					} else {
						usingRelay.Store(true)
						log.Println("switched to relay")
					}
				}
			} else if !isDead && usingRelay.Load() {
				log.Printf("udp recovered, switching back to direct connection")
				var ipcBuilder strings.Builder
				endpointCache.Range(func(key, value interface{}) bool {
					peerHexKey := key.(string)
					udpEndpoint := value.(string)
					ipcBuilder.WriteString(fmt.Sprintf("public_key=%s\n", peerHexKey))
					ipcBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", udpEndpoint))
					return true
				})

				if ipcBuilder.Len() > 0 {
					if err := WgDevice.IpcSet(ipcBuilder.String()); err != nil {
						log.Printf("failed to switch back to direct: %v", err)
					} else {
						usingRelay.Store(false)
						log.Println("switched back to direct UDP connection")
					}
				} else {
					usingRelay.Store(false)
				}
			}
			publishSnapshot(b)
		case <-ctx.Done():
			log.Println("stopping the health monitor")
			return
		}
	}
}
