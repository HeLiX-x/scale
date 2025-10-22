package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	pollInterval        = 30 * time.Second
	wireGuardListenPort = 51820
)

type Endpoint struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
	Port int    `json:"port"`
}

type PeerInfo struct {
	ID        string     `json:"id"`
	PublicKey string     `json:"public_key"`
	Endpoints []Endpoint `json:"endpoints"`
}

type EndpointResponse struct {
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	Port    string `json:"port"`
	NATType string `json:"nat_type"`
}

type PollResponse struct {
	StunToken string     `json:"stun_token"`
	Peers     []PeerInfo `json:"peers"` // FIXED TYPO: Was json::"peers"
}

type PeerConfig struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

type PeerOnlyConfig struct {
	Peers []PeerConfig `json:"peer_configs"`
}

type RegistrationConfig struct {
	AssignedIP string `json:"assigned_ip"`
}

func main() {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found, using environment variables.")
	}

	privKey, pubKey, err := generateOrLoadKeys()
	if err != nil {
		log.Fatalf("Key setup failed: %v", err)
	}

	serverURL := strings.TrimSuffix(strings.TrimSpace(os.Getenv("WG_CONTROL_SERVER")), "/")
	deviceID := strings.TrimSpace(os.Getenv("DEVICE_ID"))
	authToken := strings.TrimSpace(os.Getenv("AUTH_TOKEN"))

	if serverURL == "" || deviceID == "" || authToken == "" {
		log.Fatal("WG_CONTROL_SERVER, DEVICE_ID, and AUTH_TOKEN must be set in environment.")
	}

	wgInterface := "wg-" + deviceID

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

	// --- ADDED: Start the new unified polling loop ---
	go runServerPollingLoop(serverURL, pubKey.String(), authToken, wgInterface)

	log.Println("Client is running. Press Ctrl+C to exit.")
	waitForShutdown(configPath)
}

// --- NEW: Unified polling loop ---
func runServerPollingLoop(serverURL, publicKey, authToken, wgInterface string) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// Create a reusable HTTP client
	httpClient := &http.Client{Timeout: 10 * time.Second}

	// Run once immediately on startup, then on the ticker
	for ; ; <-ticker.C {
		log.Println("Polling server for updates...")

		// 1. Call /api/poll
		pollResp, err := pollServer(httpClient, serverURL, authToken)
		if err != nil {
			log.Printf("Error polling server: %v", err)
			continue
		}

		// 2. If we got a STUN token, call /api/stun
		if pollResp.StunToken != "" {
			ep, err := discoverEndpoint(httpClient, serverURL, pollResp.StunToken)
			if err != nil {
				log.Printf("Error discovering endpoint: %v", err)
				continue
			}

			// Determine which IP to use
			ip := ep.IPv4
			if ip == "" {
				ip = ep.IPv6
			}

			if ip == "" || ep.Port == "" {
				log.Println("STUN response did not return a valid IP or Port")
				continue
			}

			// 3. Send our discovered endpoint to the heartbeat endpoint
			// This updates our endpoint in the server's Redis cache for other peers
			endpoint := fmt.Sprintf("%s:%s", ip, ep.Port)
			if err := updateHeartbeat(httpClient, serverURL, publicKey, authToken, endpoint); err != nil {
				log.Printf("Error updating heartbeat: %v", err)
			}
		}

		// 4. Sync WireGuard peers with the list we just got
		// We need to convert the []PeerInfo to []PeerConfig
		peerConfigs := make([]PeerConfig, 0, len(pollResp.Peers))
		for _, p := range pollResp.Peers {
			// In the future, p.Endpoints will be a list.
			// For now, we just need the PublicKey and AllowedIPs
			// The server will provide the live endpoint via the GetPeerConfig logic
			peerConfigs = append(peerConfigs, PeerConfig{
				PublicKey:  p.PublicKey,
				AllowedIPs: []string{p.ID}, // This now expects the AssignedIP from the server
				// Endpoint: Will be fetched live by the server, not set here.
			})
		}

		// This function is defined in wg_dynamic.go
		if err := syncWireGuardPeers(wgInterface, peerConfigs); err != nil {
			log.Printf("Error syncing peers: %v", err)
		}
	}
}

// --- NEW: Helper for /api/poll ---
func pollServer(client *http.Client, serverURL, authToken string) (*PollResponse, error) {
	req, err := http.NewRequest("GET", serverURL+"/api/poll", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-200 status: %s", resp.Status)
	}

	var pollResp PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		return nil, err
	}

	return &pollResp, nil
}

// --- NEW: Helper for /api/stun ---
func discoverEndpoint(client *http.Client, serverURL, stunToken string) (*EndpointResponse, error) {
	stunURL := fmt.Sprintf("%s/api/stun?token=%s", serverURL, stunToken)
	resp, err := client.Get(stunURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stun endpoint returned non-200 status: %s", resp.Status)
	}

	var epResp EndpointResponse
	if err := json.NewDecoder(resp.Body).Decode(&epResp); err != nil {
		return nil, err
	}
	return &epResp, nil
}

// --- MODIFIED: Heartbeat function ---
// This is no longer a loop. It's just a simple function to send an update.
func updateHeartbeat(client *http.Client, serverURL, publicKey, authToken, endpoint string) error {
	payload, _ := json.Marshal(map[string]string{
		"public_key": publicKey,
		"endpoint":   endpoint,
	})

	req, err := http.NewRequest("POST", serverURL+"/api/devices/heartbeat", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("heartbeat request creation: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat sending: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat request failed with status: %s", resp.Status)
	}
	log.Println("Heartbeat update successful.")
	return nil
}

// --- UNCHANGED: Helper Functions Below ---

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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-OK status: %s", resp.Status)
	}
	var config RegistrationConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode server response: %w", err)
	}
	return &config, nil
}

func generateOrLoadKeys() (wgtypes.Key, wgtypes.Key, error) {
	keyPath := "private.key"
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		log.Println("No private key found. Generating a new one...")
		newKey, err := wgtypes.GenerateKey()
		if err != nil {
			return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("failed to generate private key: %w", err)
		}
		if err := os.WriteFile(keyPath, []byte(newKey.String()), 0600); err != nil {
			return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("failed to save private key: %w", err)
		}
		return newKey, newKey.PublicKey(), nil
	}
	privKey, err := wgtypes.ParseKey(string(keyBytes))
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("failed to parse private key: %w", err)
	}
	return privKey, privKey.PublicKey(), nil
}

func writeConfigFile(path, content string) error {
	configDir := "/etc/wireguard"
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", err)
		}
	}
	return os.WriteFile(path, []byte(content), 0600)
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitForShutdown(configPath string) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutdown signal received. Bringing WireGuard interface down...")
	if err := runCommand("wg-quick", "down", configPath); err != nil {
		log.Printf("wg-quick down command failed: %v", err)
	}
	log.Println("Client shut down.")
}
