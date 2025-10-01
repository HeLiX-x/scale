package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/joho/godotenv"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {

	if err := godotenv.Load(); err == nil {
		log.Println("Loaded .env file")
	}

	// Generate or load keys
	privKey, pubKey, err := generateOrLoadKeys()
	if err != nil {
		log.Fatalf("Key setup failed: %v", err)
	}

	serverURL := strings.TrimSuffix(strings.TrimSpace(os.Getenv("WG_CONTROL_SERVER")), "/")
	if serverURL == "" {
		log.Fatal("Missing WG_CONTROL_SERVER in environment")
	}

	deviceID := strings.TrimSpace(os.Getenv("DEVICE_ID"))
	if deviceID == "" {
		log.Fatal("Missing DEVICE_ID in environment")
	}

	peerConfig, err := fetchConfigFromServer(serverURL, deviceID, pubKey)
	if err != nil {
		log.Fatalf("Failed to fetch config: %v", err)
	}

	// Build DNS line
	var dnsLine string
	if len(peerConfig.DNSServers) > 0 {
		dnsLine = "DNS = " + strings.Join(peerConfig.DNSServers, ", ")
	} else {
		dnsLine = "DNS = 10.0.0.10" // fallback if server doesn't provide DNS
	}

	configContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
%s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`,
		privKey,
		peerConfig.LocalIP,
		dnsLine, // ← use dynamic DNS line
		peerConfig.ServerPublicKey,
		peerConfig.Endpoint,
		strings.Join(peerConfig.AllowedIPs, ", "),
	)

	// Define the configuration path
	configDir := "/etc/wireguard"
	configPath := configDir + "/netcafe.conf"

	// Ensure the directory exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		log.Printf("Creating directory: %s", configDir)
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatalf("Failed to create directory %s: %v", configDir, err)
		}
	}

	// Write the config file
	err = os.WriteFile(configPath, []byte(configContent), 0600)
	if err != nil {
		log.Fatalf("Failed to write config file to %s: %v. Make sure you are running with sudo.", configPath, err)
	}

	// === LAUNCH wg-quick ===
	log.Printf("Starting WireGuard via wg-quick using %s", configPath)
	cmd := exec.Command("wg-quick", "up", configPath)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	if err != nil {
		log.Fatalf("wg-quick failed: %v", err)
	}

	log.Println("WireGuard is running. Press Ctrl+C to stop.")

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down WireGuard...")
	// Tear down using wg-quick
	cmdDown := exec.Command("wg-quick", "down", configPath)
	cmdDown.Run() // ignore error on shutdown
	// We might not want to remove the config on shutdown, so the user can inspect it.
	// os.Remove(configPath)
}

// generateOrLoadKeys handles key generation and persistence
func generateOrLoadKeys() (privateKey, publicKey string, err error) {
	var pkey wgtypes.Key
	keyFileContent, err := os.ReadFile("private.key")
	if err != nil {
		// Generate new key since one doesn't exist
		pkey, err = wgtypes.GenerateKey()
		if err != nil {
			return "", "", fmt.Errorf("failed to generate private key: %w", err)
		}

		// Save the base64 encoded version to the file
		encodedKey := base64.StdEncoding.EncodeToString(pkey[:])
		if err := os.WriteFile("private.key", []byte(encodedKey), 0600); err != nil {
			return "", "", err
		}
		log.Println("Generated new private key")
	} else {
		// Decode existing base64 key from file
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyFileContent)))
		if err != nil {
			return "", "", fmt.Errorf("failed to decode private key: %w", err)
		}

		pkey, err = wgtypes.NewKey(decoded)
		if err != nil {
			return "", "", fmt.Errorf("invalid private.key: %w", err)
		}
	}

	return pkey.String(), pkey.PublicKey().String(), nil
}

// PeerConfig matches the JSON response from your control server
type PeerConfig struct {
	Endpoint        string   `json:"endpoint"`
	AllowedIPs      []string `json:"allowed_ips"`
	ServerPublicKey string   `json:"server_public_key"`
	LocalIP         string   `json:"local_ip"`
	DNSServers      []string `json:"dns_servers,omitempty"` // Allow empty DNS servers
}

// fetchConfigFromServer registers the device and fetches its config
func fetchConfigFromServer(serverURL, deviceID, publicKey string) (*PeerConfig, error) {
	hostname, _ := os.Hostname()
	reqBody, _ := json.Marshal(map[string]string{
		"device_id":  deviceID,
		"public_key": publicKey,
		"hostname":   hostname,
	})
	resp, err := http.Post(serverURL+"/register", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-200 status: %s", resp.Status)
	}

	var config PeerConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}
