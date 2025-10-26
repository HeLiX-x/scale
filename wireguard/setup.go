package main

import (
	"bytes"
	// "encoding/binary" // REMOVED - Unused
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/pion/stun/v2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	pollInterval        = 30 * time.Second
	wireGuardListenPort = 51820
	probeInterval       = 150 * time.Millisecond
	probeCount          = 5
	probeTimeout        = 3 * time.Second
	keepAliveInterval   = 20 * time.Second
)

var probeMagic = []byte{0xDE, 0xC0, 0xAD, 0xDE}
var pongMagic = []byte{0xDE, 0xC0, 0xFE, 0xED}

// --- Data Structures ---
// (Endpoint, PeerInfo, EndpointResponse, PollResponse, PeerConfig, RegistrationConfig unchanged)
type Endpoint struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Type     string `json:"type"`
}

func (e Endpoint) String() string {
	return net.JoinHostPort(e.IP, strconv.Itoa(e.Port))
}

func (e Endpoint) UDPAddr() (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", e.String())
}

type PeerInfo struct {
	ID        string     `json:"id"` // AssignedIP
	PublicKey string     `json:"public_key"`
	Endpoints []Endpoint `json:"endpoints,omitempty"`
}

type EndpointResponse struct {
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	Port    string `json:"port"`
	NATType string `json:"nat_type"`
}

type PollResponse struct {
	StunToken string     `json:"stun_token"`
	Peers     []PeerInfo `json:"peers"`
}

type PeerConfig struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

type RegistrationConfig struct {
	AssignedIP string `json:"assigned_ip"`
}

// HeartbeatPayload is the JSON structure sent to the /heartbeat endpoint
type HeartbeatPayload struct {
	SrflxEndpoint *Endpoint  `json:"srflx_endpoint,omitempty"`
	HostEndpoints []Endpoint `json:"host_endpoints,omitempty"`
}

// --- Global State ---
var (
	activeProbes sync.Map // Key: wgtypes.Key, Value: *probeState
	p2pEndpoints sync.Map // Key: wgtypes.Key, Value: *net.UDPAddr
	udpConn      *net.UDPConn
	ownPublicKey wgtypes.Key // Added global for own key
)

// --- UPDATED: probeState struct ---
type probeState struct {
	peerKey    wgtypes.Key
	candidates []*net.UDPAddr // Store resolved UDP addresses being probed
	pongChan   chan *net.UDPAddr
	cancel     chan struct{}
	mu         sync.Mutex // Protects 'active' flag
	active     bool
	probingWG  sync.WaitGroup
	// targetPubkey wgtypes.Key // No longer needed directly, peerKey serves this
}

func main() {
	// ... (godotenv load) ...
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found, using environment variables.")
	}

	privKey, pubKey, err := generateOrLoadKeys()
	if err != nil {
		log.Fatalf("Key setup failed: %v", err)
	}
	ownPublicKey = pubKey // <-- FIX: Initialize ownPublicKey

	// ... (serverURL/deviceID/authToken checks) ...
	serverURL := strings.TrimSuffix(strings.TrimSpace(os.Getenv("WG_CONTROL_SERVER")), "/")
	deviceID := strings.TrimSpace(os.Getenv("DEVICE_ID"))
	authToken := strings.TrimSpace(os.Getenv("AUTH_TOKEN"))

	if serverURL == "" || deviceID == "" || authToken == "" {
		log.Fatal("WG_CONTROL_SERVER, DEVICE_ID, and AUTH_TOKEN must be set in environment.")
	}

	wgInterface := "wg-" + deviceID

	// --- Setup Shared UDP Connection ---
	listenAddr := &net.UDPAddr{Port: wireGuardListenPort}
	udpConn, err = net.ListenUDP("udp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP port %d: %v", wireGuardListenPort, err)
	}
	defer udpConn.Close()
	log.Printf("Listening for UDP on %s", udpConn.LocalAddr().String())

	// --- Start UDP Listener ---
	go startUDPListener(udpConn) // Pass the connection

	// ... (Registration, Config Write, wg-quick up) ...
	log.Println("Registering with control server...")
	regConfig, err := registerDeviceAndGetIP(serverURL, pubKey.String(), authToken)
	if err != nil {
		log.Fatalf("Failed to register device: %v", err)
	}
	log.Printf("Successfully registered. Assigned IP: %s", regConfig.AssignedIP)

	configContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
ListenPort = %d
`, privKey.String(), regConfig.AssignedIP, wireGuardListenPort)
	configPath := "/etc/wireguard/" + wgInterface + ".conf"

	if err := writeConfigFile(configPath, configContent); err != nil {
		log.Fatalf("Failed to write config file: %v. Ensure you are running with sudo.", err)
	}

	log.Printf("Starting WireGuard interface '%s'...", wgInterface)
	if err := runCommand("wg-quick", "up", configPath); err != nil {
		log.Fatalf("wg-quick up failed: %v", err)
	}

	log.Println("WireGuard is running. Starting background services.")
	go runServerPollingLoop(serverURL, pubKey.String(), authToken, wgInterface)
	go runP2PKeepAlives(udpConn)

	log.Println("Client is running. Press Ctrl+C to exit.")
	waitForShutdown(configPath)
}

// --- UPDATED: UDP Listener Goroutine ---
func startUDPListener(conn *net.UDPConn) {
	buffer := make([]byte, 1500) // MTU size buffer
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && !netErr.Timeout() && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("Error reading from UDP socket: %v", err)
			}
			// Prevent tight loop on errors like closed connection
			time.Sleep(100 * time.Millisecond)
			continue
		}

		packet := buffer[:n]

		// --- Check for PONG ---
		if bytes.Equal(packet, pongMagic) {
			log.Printf("Received PONG from %s", remoteAddr.String())
			foundMatch := false
			// Iterate through active probes to find which one this pong belongs to
			activeProbes.Range(func(key, value interface{}) bool {
				state := value.(*probeState)
				state.mu.Lock() // Lock state while checking candidates
				isActive := state.active
				state.mu.Unlock()

				if !isActive {
					return true
				} // Skip inactive probes

				// --- FIX: Check if remoteAddr matches one of the candidates being probed ---
				for _, candidateAddr := range state.candidates {
					if candidateAddr.IP.Equal(remoteAddr.IP) && candidateAddr.Port == remoteAddr.Port {
						log.Printf("PONG from %s matches probe candidate for peer %s", remoteAddr.String(), state.peerKey.String()[:8])
						// Signal the specific probe goroutine
						select {
						case state.pongChan <- remoteAddr:
							log.Printf("Signaled success to probe goroutine for %s", state.peerKey.String()[:8])
						default:
							log.Printf("Pong received for %s but channel blocked/closed.", state.peerKey.String()[:8])
						}
						foundMatch = true
						return false // Stop iterating Range once matched
					}
				}
				return true // Continue iterating Range
			})
			if !foundMatch {
				log.Printf("Received PONG from %s but found no matching active probe candidate.", remoteAddr.String())
			}
		} else if bytes.Equal(packet, probeMagic) {
			// --- Respond to PROBE ---
			log.Printf("Received PROBE from %s, sending PONG back.", remoteAddr.String())
			_, err := conn.WriteToUDP(pongMagic, remoteAddr)
			if err != nil {
				log.Printf("Error sending PONG to %s: %v", remoteAddr.String(), err)
			}
		} else {
			// --- Likely WireGuard traffic ---
			// Let the kernel/WireGuard handle it. No action needed here.
			// You might add metrics here later if desired.
		}
	}
}

// --- runP2PKeepAlives (Unchanged from previous version) ---
func runP2PKeepAlives(conn *net.UDPConn) {
	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()

	for range ticker.C {
		p2pEndpoints.Range(func(key, value interface{}) bool {
			peerKey := key.(wgtypes.Key)
			endpoint := value.(*net.UDPAddr)
			// log.Printf("Sending keep-alive probe to peer %s at %s", peerKey.String()[:8], endpoint.String())
			_, err := conn.WriteToUDP(probeMagic, endpoint)
			if err != nil {
				log.Printf("Error sending keep-alive to %s (%s): %v", peerKey.String()[:8], endpoint.String(), err)
				// Consider removing endpoint after multiple failures
			}
			return true // Continue iterating
		})
	}
}

// --- UPDATED: Per-Peer Probing Goroutine ---
func probePeer(conn *net.UDPConn, peer PeerInfo, wgInterface string) {
	peerKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		log.Printf("Invalid public key %s for probing, skipping.", peer.PublicKey)
		return
	}

	// Double-check if already probing or connected P2P
	if _, loaded := activeProbes.LoadOrStore(peerKey, &probeState{}); loaded {
		log.Printf("Probing already in progress for peer %s", peerKey.String()[:8])
		return // LoadOrStore stored a dummy if not present, check loaded flag
	}
	defer activeProbes.Delete(peerKey) // Ensure cleanup on exit

	if _, ok := p2pEndpoints.Load(peerKey); ok {
		// log.Printf("Already have P2P endpoint for peer %s, skipping probe.", peerKey.String()[:8])
		return
	}

	// --- Resolve candidates first ---
	resolvedCandidates := []*net.UDPAddr{}
	candidateEndpoints := []Endpoint{} // Store original endpoints for state

	// Prioritize host > srflx
	for _, ep := range peer.Endpoints {
		if ep.Type == "host" && ep.Protocol == "udp" {
			candidateEndpoints = append(candidateEndpoints, ep)
		}
	}
	for _, ep := range peer.Endpoints {
		if ep.Type == "srflx" && ep.Protocol == "udp" {
			candidateEndpoints = append(candidateEndpoints, ep)
		}
	}
	// TODO: Add relay

	if len(candidateEndpoints) == 0 {
		log.Printf("No UDP candidates to probe for peer %s", peerKey.String()[:8])
		return
	}

	// Resolve the addresses
	for _, candidate := range candidateEndpoints {
		addr, err := candidate.UDPAddr()
		if err != nil {
			log.Printf("Invalid candidate address %s for peer %s: %v", candidate.String(), peerKey.String()[:8], err)
			continue
		}
		resolvedCandidates = append(resolvedCandidates, addr)
	}

	if len(resolvedCandidates) == 0 {
		log.Printf("No resolvable UDP candidates for peer %s", peerKey.String()[:8])
		return
	}

	// --- Initialize probe state ---
	state := &probeState{
		peerKey:    peerKey,
		candidates: resolvedCandidates, // <-- FIX: Store resolved addrs
		pongChan:   make(chan *net.UDPAddr, 1),
		cancel:     make(chan struct{}),
		active:     true,
	}
	// Store the actual state object back into the map
	activeProbes.Store(peerKey, state)

	// Cleanup function using defer
	defer func() {
		state.mu.Lock()
		state.active = false
		state.mu.Unlock()
		close(state.cancel)    // Signal cancellation
		state.probingWG.Wait() // Wait for senders
		// activeProbes.Delete(peerKey) // Already deferred in LoadOrStore check
		log.Printf("Finished probing attempt for peer %s", peerKey.String()[:8])
	}()

	log.Printf("Starting probe for peer %s (%s) with %d resolved candidates.", peerKey.String()[:8], peer.ID, len(resolvedCandidates))

	// --- Launch probe senders ---
	for _, addr := range resolvedCandidates {
		state.probingWG.Add(1)
		go func(targetAddr *net.UDPAddr) {
			defer state.probingWG.Done()
			for i := 0; i < probeCount; i++ {
				select {
				case <-state.cancel:
					return // Abort if cancelled
				default:
					// Send probeMagic
					_, err := conn.WriteToUDP(probeMagic, targetAddr)
					if err != nil {
						// Log infrequent errors, avoid flooding logs
						if i == 0 || i == probeCount-1 {
							log.Printf("Error sending probe %d to %s @ %s: %v", i+1, peerKey.String()[:8], targetAddr.String(), err)
						}
						// Don't necessarily stop, NAT might fix itself
					}
					// Wait or check cancel again
					select {
					case <-time.After(probeInterval): // Wait interval
					case <-state.cancel:
						return // Abort if cancelled during wait
					}
				}
			}
		}(addr)
	}

	// --- Wait for result ---
	select {
	case pongAddr := <-state.pongChan: // Success! Pong received
		log.Printf("SUCCESS: Received pong from peer %s via %s!", peerKey.String()[:8], pongAddr.String())
		p2pEndpoints.Store(peerKey, pongAddr)                              // Store successful endpoint
		err := updateWireguardPeerEndpoint(wgInterface, peerKey, pongAddr) // Update WG
		if err != nil {
			log.Printf("ERROR: Failed to update WireGuard endpoint for peer %s: %v", peerKey.String()[:8], err)
			p2pEndpoints.Delete(peerKey) // Rollback if WG update fails
		} else {
			log.Printf("WireGuard endpoint updated successfully for peer %s to %s", peerKey.String()[:8], pongAddr.String())
		}

	case <-time.After(probeTimeout): // Timeout
		log.Printf("TIMEOUT: No pong received from peer %s within %v.", peerKey.String()[:8], probeTimeout)
		// TODO: Trigger relay fallback (Phase 3)
	}
}

// --- Polling loop to run the poll cycle ---
func runServerPollingLoop(serverURL, publicKey, authToken, wgInterface string) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	httpClient := &http.Client{Timeout: 10 * time.Second}
	var lastSrflxEndpoint *Endpoint

	// Run once immediately on startup
	performPollCycle(httpClient, serverURL, publicKey, authToken, wgInterface, &lastSrflxEndpoint, udpConn)

	for range ticker.C {
		performPollCycle(httpClient, serverURL, publicKey, authToken, wgInterface, &lastSrflxEndpoint, udpConn)
	}
}

// --- performPollCycle (Minor change: Call syncWireGuardPeers correctly) ---
func performPollCycle(httpClient *http.Client, serverURL, publicKey, authToken, wgInterface string, lastSrflxEndpoint **Endpoint, conn *net.UDPConn) {
	// ... (Candidate Gathering, Poll, STUN, Heartbeat - unchanged) ...
	log.Println("Polling server for updates...")
	var currentSrflxEndpoint *Endpoint
	var currentHostEndpoints []Endpoint

	// 1. Discover local host candidates
	hostEps, err := getLocalEndpoints(wireGuardListenPort)
	if err != nil {
		log.Printf("Error getting local endpoints: %v", err)
	}
	currentHostEndpoints = hostEps

	// 2. Poll server
	pollResp, err := pollServer(httpClient, serverURL, authToken, publicKey)
	if err != nil {
		log.Printf("Error polling server: %v", err)
		return
	}

	// 3. Perform STUN discovery
	ep, err := discoverUDPReflexiveAddr(conn, "stun.l.google.com:19302")
	if err != nil {
		log.Printf("UDP STUN discovery failed: %v. Using last known srflx endpoint.", err)
		currentSrflxEndpoint = *lastSrflxEndpoint // Use cached
	} else {
		log.Printf("Discovered UDP srflx candidate: %s (via real STUN)", ep.String())
		currentSrflxEndpoint = ep
		*lastSrflxEndpoint = currentSrflxEndpoint // Update cache
	}

	// 4. Report candidates via Heartbeat
	if err := updateHeartbeat(httpClient, serverURL, publicKey, authToken, currentSrflxEndpoint, currentHostEndpoints); err != nil {
		log.Printf("Error updating heartbeat: %v", err)
	}

	// 5. Process Peer List & Initiate Probes
	currentPeers := make(map[wgtypes.Key]bool)
	peerConfigsForWg := make([]PeerConfig, 0, len(pollResp.Peers))

	for _, peer := range pollResp.Peers {
		peerKey, keyErr := wgtypes.ParseKey(peer.PublicKey)
		if keyErr != nil {
			log.Printf("Skipping peer with invalid key: %v", keyErr)
			continue
		}
		currentPeers[peerKey] = true

		// Basic WG config (no endpoint initially)
		peerConfigsForWg = append(peerConfigsForWg, PeerConfig{
			PublicKey:  peer.PublicKey,
			AllowedIPs: []string{peer.ID}, // Peer.ID holds AssignedIP
		})

		// Initiate Probing if needed
		if len(peer.Endpoints) > 0 {
			if _, connected := p2pEndpoints.Load(peerKey); !connected {
				// Use LoadOrStore to prevent race condition if multiple cycles trigger probe near-simultaneously
				if _, loaded := activeProbes.LoadOrStore(peerKey, &probeState{}); !loaded { // If we just stored the dummy...
					activeProbes.Delete(peerKey) // Remove dummy state...
					log.Printf("Launching probe goroutine for peer %s", peerKey.String()[:8])
					go probePeer(udpConn, peer, wgInterface) // And launch the real probe
				} else {
					// log.Printf("Probe already in progress for peer %s (LoadOrStore)", peerKey.String()[:8])
				}
			}
		} else {
			// Peer has no endpoints, clean up P2P status if exists
			if _, connected := p2pEndpoints.LoadAndDelete(peerKey); connected {
				log.Printf("Peer %s has no endpoints reported, removing P2P status.", peerKey.String()[:8])
				// Reset WireGuard endpoint to potentially allow relay fallback later
				go updateWireguardPeerEndpoint(wgInterface, peerKey, nil)
			}
		}
	}

	// Sync WireGuard base config (adds/removes peers, updates AllowedIPs)
	// --- FIX: Pass 'true' for replacePeers ---
	if err := syncWireGuardPeers(wgInterface, peerConfigsForWg, true); err != nil {
		log.Printf("Error syncing WireGuard peers: %v", err)
	}

	// Cleanup old P2P endpoints
	p2pEndpoints.Range(func(key, value interface{}) bool {
		peerKey := key.(wgtypes.Key)
		if _, stillExists := currentPeers[peerKey]; !stillExists {
			log.Printf("Peer %s no longer reported by server, removing P2P endpoint.", peerKey.String()[:8])
			p2pEndpoints.Delete(peerKey)
			// WG peer itself will be removed by syncWireGuardPeers above
		}
		return true
	})
}

// --- Helper functions ---
// (pollServer, discoverEndpoint, updateHeartbeat, registerDeviceAndGetIP, generateOrLoadKeys, writeConfigFile, runCommand, waitForShutdown - unchanged from previous corrected version)
// --- MODIFIED: pollServer now sends client public key ---
func pollServer(client *http.Client, serverURL, authToken, clientPubKey string) (*PollResponse, error) {
	req, err := http.NewRequest("GET", serverURL+"/api/poll", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Device-Public-Key", clientPubKey) // Add self public key

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read body for debugging
		return nil, fmt.Errorf("server returned non-200 status %s: %s", resp.Status, string(bodyBytes))
	}

	var pollResp PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		return nil, err
	}

	return &pollResp, nil
}

func discoverUDPReflexiveAddr(conn *net.UDPConn, stunServerAddr string) (*Endpoint, error) {
	// 1. Resolve the STUN server address
	serverAddr, err := net.ResolveUDPAddr("udp", stunServerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN server address: %w", err)
	}

	// 2. Build a STUN Binding Request
	message := stun.MustBuild(stun.BindingRequest, stun.TransactionID)

	// 3. Send the request
	//    We set a deadline on the connection to handle timeouts.
	if err := conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set write deadline: %w", err)
	}
	if _, err := conn.WriteTo(message.Raw, serverAddr); err != nil {
		return nil, fmt.Errorf("failed to send STUN request: %w", err)
	}

	// 4. Read the response
	buf := make([]byte, 1500)
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read STUN response: %w", err)
	}

	// 5. Reset the deadlines
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("Warning: failed to clear read deadline: %v", err) // Non-fatal
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		log.Printf("Warning: failed to clear write deadline: %v", err) // Non-fatal
	}

	// 6. Parse the response
	// 6. Parse the response
	resp := new(stun.Message)
	resp.Raw = buf[:n]                    // <-- Assign the raw bytes first
	if err := resp.Decode(); err != nil { // <-- Then call Decode with no arguments
		return nil, fmt.Errorf("failed to decode STUN response: %w", err)
	}

	// 7. Check for success
	if resp.Type != stun.BindingSuccess {
		return nil, fmt.Errorf("STUN request was not successful: %s", resp.Type)
	}

	// 8. Extract the XOR-Mapped Address
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(resp); err != nil {
		return nil, fmt.Errorf("failed to get XOR-Mapped-Address from STUN response: %w", err)
	}

	// Success!
	return &Endpoint{
		IP:       xorAddr.IP.String(),
		Port:     xorAddr.Port,
		Protocol: "udp",
		Type:     "srflx",
	}, nil
}

// updateHeartbeat sends the client's current endpoints to the control server
func updateHeartbeat(client *http.Client, serverURL, publicKey, authToken string, srflx *Endpoint, hosts []Endpoint) error {
	payload := HeartbeatPayload{
		SrflxEndpoint: srflx,
		HostEndpoints: hosts,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	// IMPORTANT: Make sure this API path matches your server's routes.go
	req, err := http.NewRequest("POST", serverURL+"/api/devices/heartbeat", bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create heartbeat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Device-Public-Key", publicKey) // Server needs to know who this is

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat server returned non-200 status %s: %s", resp.Status, string(bodyBytes))
	}

	// log.Println("Heartbeat update successful.") // Optional: can be noisy
	return nil
}

// getLocalEndpoints finds suitable local host IP addresses.
func getLocalEndpoints(port int) ([]Endpoint, error) {
	var endpoints []Endpoint
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, i := range ifaces {
		// Skip down, loopback, and virtual/docker interfaces
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 ||
			strings.Contains(i.Name, "virtual") || strings.Contains(i.Name, "docker") || strings.Contains(i.Name, "veth") {
			continue
		}

		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			// Add both IPv4 and IPv6 host candidates
			if ip.To4() != nil {
				endpoints = append(endpoints, Endpoint{
					IP:       ip.String(),
					Port:     port,
					Protocol: "udp",
					Type:     "host",
				})
			} else if ip.To16() != nil && !ip.IsLinkLocalUnicast() {
				// You can also add IPv6 if your network supports it
				// endpoints = append(endpoints, Endpoint{...})
			}
		}
	}
	return endpoints, nil
}

// --- registerDeviceAndGetIP is unchanged ---
func registerDeviceAndGetIP(serverURL, publicKey, authToken string) (*RegistrationConfig, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"public_key": publicKey,
	})
	req, err := http.NewRequest("POST", serverURL+"/api/devices/register", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
	resp, err := http.DefaultClient.Do(req) // Use DefaultClient for simple requests
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned non-OK status %s: %s", resp.Status, string(bodyBytes))
	}
	var config RegistrationConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode server response: %w", err)
	}
	return &config, nil
}

// --- generateOrLoadKeys is unchanged ---
func generateOrLoadKeys() (wgtypes.Key, wgtypes.Key, error) {
	keyPath := "private.key"
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		// Error is likely os.ErrNotExist, but handle generally
		log.Println("No private key found or error reading file. Generating a new one...")
		newKey, err := wgtypes.GenerateKey()
		if err != nil {
			return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("failed to generate private key: %w", err)
		}
		// Attempt to save the new key
		if err := os.WriteFile(keyPath, []byte(newKey.String()), 0600); err != nil {
			// Log warning but proceed with the key in memory
			log.Printf("Warning: failed to save new private key to %s: %v", keyPath, err)
		} else {
			log.Printf("Saved new private key to %s", keyPath)
		}
		return newKey, newKey.PublicKey(), nil
	}
	// If file read was successful
	privKey, err := wgtypes.ParseKey(string(keyBytes))
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("failed to parse existing private key from %s: %w", keyPath, err)
	}
	log.Printf("Loaded private key from %s", keyPath)
	return privKey, privKey.PublicKey(), nil
}

// --- writeConfigFile is unchanged ---
func writeConfigFile(path, content string) error {
	// Ensure directory exists
	configDir := "/etc/wireguard" // Consider making this configurable or relative for non-root users
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		// Attempt to create directory with appropriate permissions
		if err := os.MkdirAll(configDir, 0755); err != nil { // 0755 allows owner rwx, group rx, others rx
			return fmt.Errorf("failed to create directory %s: %w. Check permissions.", configDir, err)
		}
		log.Printf("Created directory %s", configDir)
	} else if err != nil {
		// Handle other errors during Stat
		return fmt.Errorf("failed to check directory %s: %w", configDir, err)
	}

	// Write file with restricted permissions (owner read/write only)
	err := os.WriteFile(path, []byte(content), 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file %s: %w. Check permissions.", path, err)
	}
	log.Printf("Successfully wrote config to %s", path)
	return nil
}

// --- runCommand is unchanged ---
func runCommand(name string, args ...string) error {
	log.Printf("Running command: %s %s", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	// Capture output for better debugging
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Log command, error, and output streams
		log.Printf("Command '%s %s' failed: %v", name, strings.Join(args, " "), err)
		if stdout.Len() > 0 {
			log.Printf("Stdout:\n%s", stdout.String())
		}
		if stderr.Len() > 0 {
			log.Printf("Stderr:\n%s", stderr.String())
		}
		return fmt.Errorf("command execution failed: %w", err)
	}
	// Log success and stdout if any
	log.Printf("Command '%s %s' completed successfully.", name, strings.Join(args, " "))
	if stdout.Len() > 0 {
		log.Printf("Stdout:\n%s", stdout.String())
	}
	return nil
}

// --- waitForShutdown is unchanged ---
func waitForShutdown(configPath string) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh // Block until a signal is received
	log.Println("Shutdown signal received. Bringing WireGuard interface down...")

	// Attempt to bring down the interface using wg-quick
	if err := runCommand("wg-quick", "down", configPath); err != nil {
		// Log the error but don't necessarily stop the shutdown process
		log.Printf("wg-quick down command failed: %v. Manual cleanup might be needed.", err)
	} else {
		log.Printf("WireGuard interface %s brought down successfully.", configPath)
	}

	// Optionally remove the config file on shutdown? Be careful with this.
	// if err := os.Remove(configPath); err != nil {
	//     log.Printf("Warning: Failed to remove config file %s: %v", configPath, err)
	// }

	log.Println("Client shut down.")
	// os.Exit(0) // Optionally force exit if needed
}
