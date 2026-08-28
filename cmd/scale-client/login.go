package main

import (
	"bufio"
	"flag"
	"fmt"
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
	server := firstNonEmpty(*serverFlag, os.Getenv("WG_CONTROL_SERVER"), cfg.ControlServer)
	relay := firstNonEmpty(*relayFlag, os.Getenv("RELAY_URL"), cfg.RelayURL)

	in := bufio.NewReader(os.Stdin)
	if server == "" {
		fmt.Fprint(os.Stderr, "Control server URL: ")
		line, err := in.ReadString('\n')
		if err != nil {
			return err
		}
		server = strings.TrimSpace(line)
	}
	if server == "" {
		return fmt.Errorf("control server URL is required")
	}
	server = strings.TrimSuffix(server, "/")

	if relay == "" {
		fmt.Fprint(os.Stderr, "Relay URL (optional, press Enter to skip): ")
		line, err := in.ReadString('\n')
		if err != nil {
			return err
		}
		relay = strings.TrimSpace(line)
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
