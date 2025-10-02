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
	heartbeatInterval  = 30 * time.Second
	peerUpdateInterval = 5 * time.Minute
	wgInterface        = "netcafe"
)

type PeerConfig struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

// FIX: This struct is now only for the peer configuration response.
type PeerOnlyConfig struct {
	Peers []PeerConfig `json:"peer_configs"`
}

// FIX: This new struct is specifically for the registration response.
type RegistrationConfig struct {
	AssignedIP string `json:"assigned_ip"`
}

func main() {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found, using environment variables.")
	}

	// 1. Initial Setup
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

	// 2. FIX: Register device and get assigned IP first.
	log.Println("Registering with control server...")
	regConfig, err := registerDeviceAndGetIP(serverURL, pubKey.String(), authToken)
	if err != nil {
		log.Fatalf("Failed to register device: %v", err)
	}
	log.Printf("Successfully registered. Assigned IP: %s", regConfig.AssignedIP)

	// 3. Write a minimal config file.
	configContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
`, privKey.String(), regConfig.AssignedIP) // Use the IP from the registration config
	configPath := "/etc/wireguard/" + wgInterface + ".conf"

	if err := writeConfigFile(configPath, configContent); err != nil {
		log.Fatalf("Failed to write config file: %v. Ensure you are running with sudo.", err)
	}

	// 4. Start WireGuard interface
	log.Printf("Starting WireGuard interface '%s'...", wgInterface)
	if err := runCommand("wg-quick", "up", configPath); err != nil {
		log.Fatalf("wg-quick up failed: %v", err)
	}

	// 5. FIX: Fetch the initial peer list in a separate step.
	log.Println("Performing initial peer sync...")
	peerConfig, err := fetchPeerConfig(serverURL, deviceID, authToken)
	if err != nil {
		log.Printf("Initial peer fetch failed: %v. Will retry.", err)
	} else {
		if err := syncWireGuardPeers(wgInterface, peerConfig.Peers); err != nil {
			log.Printf("Initial peer sync failed: %v. Will retry.", err)
		}
	}

	// 6. Start Background Tasks
	log.Println("WireGuard is running. Starting background services.")
	go runHeartbeat(serverURL, pubKey.String(), authToken) // Use public key for heartbeat
	go runPeerUpdater(serverURL, deviceID, authToken)

	// 7. Wait for Shutdown Signal
	log.Println("Client is running. Press Ctrl+C to exit.")
	waitForShutdown(configPath)
}

// --- Background Goroutines ---

// FIX: Heartbeat now uses public key to identify the device.
func runHeartbeat(serverURL, publicKey, authToken string) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		log.Println("Sending heartbeat...")

		payload, _ := json.Marshal(map[string]string{
			"public_key": publicKey,
			"endpoint":   "1.2.3.4:56789", // Placeholder for NAT traversal
		})

		req, err := http.NewRequest("POST", serverURL+"/api/devices/heartbeat", bytes.NewReader(payload))
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

func runPeerUpdater(serverURL, deviceID, authToken string) {
	ticker := time.NewTicker(peerUpdateInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		log.Println("Checking for peer updates...")

		config, err := fetchPeerConfig(serverURL, deviceID, authToken)
		if err != nil {
			log.Printf("Peer update error (fetching): %v", err)
			continue
		}

		if err := syncWireGuardPeers(wgInterface, config.Peers); err != nil {
			log.Printf("Peer update error (syncing): %v", err)
		}
	}
}

// --- Helper Functions ---

// FIX: New function to handle device registration.
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

// FIX: Renamed from fetchFullConfig to be more specific.
func fetchPeerConfig(serverURL, deviceID, authToken string) (*PeerOnlyConfig, error) {
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
	var config PeerOnlyConfig
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
			return fmt.Errorf("failed to create directory %s: %w", configDir, err)
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
