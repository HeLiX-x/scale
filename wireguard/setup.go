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
	// How often to send a heartbeat to the server.
	heartbeatInterval = 30 * time.Second
	// How often to check for new peers using the optimized wgctrl logic.
	peerUpdateInterval = 5 * time.Minute
	// The name of the WireGuard interface.
	wgInterface = "netcafe"
)

// PeerConfig matches the JSON response from your control server.
type PeerConfig struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

// FullConfig matches the JSON response from the registration endpoint.
type FullConfig struct {
	AssignedIP string       `json:"assigned_ip"`
	Peers      []PeerConfig `json:"peer_configs"`
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables.")
	}

	// 1. Initial Setup
	privKey, _, err := generateOrLoadKeys()
	if err != nil {
		log.Fatalf("Key setup failed: %v", err)
	}

	serverURL := strings.TrimSuffix(strings.TrimSpace(os.Getenv("WG_CONTROL_SERVER")), "/")
	deviceID := strings.TrimSpace(os.Getenv("DEVICE_ID"))
	authToken := strings.TrimSpace(os.Getenv("AUTH_TOKEN"))

	if serverURL == "" || deviceID == "" || authToken == "" {
		log.Fatal("WG_CONTROL_SERVER, DEVICE_ID, and AUTH_TOKEN must be set in environment.")
	}

	// 2. Fetch Initial Configuration
	log.Println("Registering with control server...")
	initialConfig, err := fetchFullConfig(serverURL, deviceID, authToken)
	if err != nil {
		log.Fatalf("Failed to fetch initial config: %v", err)
	}

	// 3. Write a minimal config file. Peers will be added dynamically.
	configContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
`, privKey.String(), initialConfig.AssignedIP)
	configPath := "/etc/wireguard/" + wgInterface + ".conf"

	if err := writeConfigFile(configPath, configContent); err != nil {
		log.Fatalf("Failed to write config file: %v. Ensure you are running with sudo.", err)
	}

	// 4. Start WireGuard interface
	log.Printf("Starting WireGuard interface '%s'...", wgInterface)
	if err := runCommand("wg-quick", "up", configPath); err != nil {
		log.Fatalf("wg-quick up failed: %v", err)
	}

	// 5. Perform the first peer sync immediately
	log.Println("Performing initial peer sync...")
	if err := syncWireGuardPeers(wgInterface, initialConfig.Peers); err != nil {
		log.Printf("Initial peer sync failed: %v. Will retry.", err)
	}

	// 6. Start Background Tasks
	log.Println("WireGuard is running. Starting background services.")
	go runHeartbeat(serverURL, deviceID, authToken)   // This logic is unchanged.
	go runPeerUpdater(serverURL, deviceID, authToken) // This now uses the optimized logic.

	// 7. Wait for Shutdown Signal
	log.Println("Client is running. Press Ctrl+C to exit.")
	waitForShutdown(configPath)
}

// --- Background Goroutines ---

// runHeartbeat contains the existing, robust heartbeat logic which remains unchanged.
func runHeartbeat(serverURL, deviceID, authToken string) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		log.Println("Sending heartbeat...")

		payload, _ := json.Marshal(map[string]string{
			"device_id": deviceID,
			"endpoint":  "1.2.3.4:56789", // Placeholder for NAT traversal
		})

		req, err := http.NewRequest("POST", serverURL+"/api/heartbeat", bytes.NewReader(payload))
		if err != nil {
			log.Printf("Heartbeat error (request creation): %v", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("Heartbeat error (sending): %v", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("Heartbeat request failed with status: %s", resp.Status)
		}
		resp.Body.Close()
	}
}

// runPeerUpdater now uses the highly efficient syncWireGuardPeers function.
func runPeerUpdater(serverURL, deviceID, authToken string) {
	ticker := time.NewTicker(peerUpdateInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		log.Println("Checking for peer updates...")

		config, err := fetchFullConfig(serverURL, deviceID, authToken)
		if err != nil {
			log.Printf("Peer update error (fetching): %v", err)
			continue
		}

		// Call the optimized function from wg_dynamic.go
		if err := syncWireGuardPeers(wgInterface, config.Peers); err != nil {
			log.Printf("Peer update error (syncing): %v", err)
		}
	}
}

// --- Helper Functions ---
// (These functions support the main logic)

func generateOrLoadKeys() (wgtypes.Key, wgtypes.Key, error) {
	// ... (This function is unchanged)
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

func fetchFullConfig(serverURL, deviceID, authToken string) (*FullConfig, error) {
	// ... (This function is unchanged)
	url := fmt.Sprintf("%s/api/devices/%s/peers", serverURL, deviceID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-OK status: %s", resp.Status)
	}
	var config FullConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode server response: %w", err)
	}
	return &config, nil
}

func writeConfigFile(path, content string) error {
	// ... (This function is unchanged)
	configDir := "/etc/wireguard"
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", configDir, err)
		}
	}
	return os.WriteFile(path, []byte(content), 0600)
}

func runCommand(name string, args ...string) error {
	// ... (This function is unchanged)
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitForShutdown(configPath string) {
	// ... (This function is unchanged)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutdown signal received. Bringing WireGuard interface down...")
	if err := runCommand("wg-quick", "down", configPath); err != nil {
		log.Printf("wg-quick down command failed: %v", err)
	}
	log.Println("Client shut down.")
}
