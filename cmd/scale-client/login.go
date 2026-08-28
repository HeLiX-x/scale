package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"golang.org/x/term"
)

func cmdLogin(args []string) error {
	_ = godotenv.Load(".env")

	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverFlag := fs.String("server", "", "Control plane URL")
	relayFlag := fs.String("relay", "", "Relay WebSocket URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := loadConfig()
	server := firstNonEmpty(*serverFlag, cfg.ControlServer, os.Getenv("WG_CONTROL_SERVER"), DefaultControlServer)
	relay := firstNonEmpty(*relayFlag, cfg.RelayURL, os.Getenv("RELAY_URL"), DefaultRelayURL)
	server = strings.TrimSuffix(server, "/")

	in := bufio.NewReader(os.Stdin)

	fmt.Fprint(os.Stderr, "Email: ")
	email, err := in.ReadString('\n')
	if err != nil {
		return err
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}

	fmt.Fprint(os.Stderr, "Password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	password := strings.TrimSpace(string(pwBytes))
	if password == "" {
		return fmt.Errorf("password is required")
	}

	token, err := loginToServer(server, email, password)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if err := writeToken(token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	cfg.ControlServer = server
	if relay != "" {
		cfg.RelayURL = relay
	}
	if err := saveConfig(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("Login successful! Token saved to ~/.scale/token")
	fmt.Println("Run 'sudo scale up' to start the VPN.")
	return nil
}

func cmdRegister(args []string) error {
	_ = godotenv.Load(".env")

	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serverFlag := fs.String("server", "", "Control plane URL")
	relayFlag := fs.String("relay", "", "Relay WebSocket URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := loadConfig()
	server := firstNonEmpty(*serverFlag, cfg.ControlServer, os.Getenv("WG_CONTROL_SERVER"), DefaultControlServer)
	relay := firstNonEmpty(*relayFlag, cfg.RelayURL, os.Getenv("RELAY_URL"), DefaultRelayURL)
	server = strings.TrimSuffix(server, "/")

	in := bufio.NewReader(os.Stdin)

	fmt.Fprint(os.Stderr, "Name: ")
	name, err := in.ReadString('\n')
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("name is required")
	}

	fmt.Fprint(os.Stderr, "Email: ")
	email, err := in.ReadString('\n')
	if err != nil {
		return err
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}

	fmt.Fprint(os.Stderr, "Password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	password := strings.TrimSpace(string(pwBytes))
	if password == "" {
		return fmt.Errorf("password is required")
	}

	if err := registerUserOnServer(server, name, email, password); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	token, err := loginToServer(server, email, password)
	if err != nil {
		return fmt.Errorf("auto-login failed: %w", err)
	}
	if err := writeToken(token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	cfg.ControlServer = server
	if relay != "" {
		cfg.RelayURL = relay
	}
	if err := saveConfig(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Account created successfully! Logged in as %s.\nToken saved to ~/.scale/token\nRun 'sudo scale up' to start the VPN.\n", email)
	return nil
}

func registerUserOnServer(serverUrl, name, email, password string) error {
	payload, err := json.Marshal(map[string]string{
		"name":     name,
		"email":    email,
		"password": password,
	})
	if err != nil {
		return err
	}

	resp, err := http.Post(serverUrl+"/api/register", "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errMap map[string]interface{}
		if json.NewDecoder(resp.Body).Decode(&errMap) == nil {
			if errMsg, ok := errMap["error"].(string); ok && errMsg != "" {
				return fmt.Errorf("%s", errMsg)
			}
		}
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

func cmdLogout(_ []string) error {
	_ = os.Remove(tokenPath())

	if _, err := os.Stat(keyPath()); err == nil {
		fmt.Fprint(os.Stderr, "Delete WireGuard identity (~/.scale/wg.key)? [y/N]: ")
		in := bufio.NewReader(os.Stdin)
		line, _ := in.ReadString('\n')
		ans := strings.ToLower(strings.TrimSpace(line))
		if ans == "y" || ans == "yes" {
			_ = os.Remove(keyPath())
		}
	}

	fmt.Println("Logged out successfully. Local credentials cleared.")
	return nil
}
