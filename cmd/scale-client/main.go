package main

import (
	"fmt"
	"os"
	"runtime"
)

var (
	Version   = "v1.0.0"
	GitCommit = "dev"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	cmd := args[0]
	rest := args[1:]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		printUsage()
		return
	}
	if cmd == "--version" {
		cmd = "version"
	}

	var err error
	switch cmd {
	case "register":
		err = cmdRegister(rest)
	case "login":
		err = cmdLogin(rest)
	case "up":
		err = cmdUp(rest)
	case "status":
		err = cmdStatus(rest)
	case "peers":
		err = cmdPeers(rest)
	case "down":
		err = cmdDown(rest)
	case "logout":
		err = cmdLogout(rest)
	case "bugreport":
		err = cmdBugreport(rest)
	case "version":
		err = cmdVersion(rest)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Scale VPN — mesh WireGuard client

Usage:
  scale <command>

Commands:
  register    Create a new user account & log in
  login       Interactive login; saves JWT to ~/.scale/token
  up          Start VPN tunnel, poller, and health monitor
  status      Show client status, assigned IP, and relay state
  peers       Table of mesh peers and ping status
  down        Stop VPN session and remove wg0
  logout      Clear local token and credentials
  bugreport   Write a redacted diagnostic snapshot
  version     Show build version, git commit, and architecture
`)
}

func cmdVersion(_ []string) error {
	fmt.Printf("Scale VPN Client %s\n", Version)
	fmt.Printf("  Git commit:  %s\n", GitCommit)
	fmt.Printf("  Built:       %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  Go:          %s\n", runtime.Version())
	return nil
}
