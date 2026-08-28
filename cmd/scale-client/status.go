package main

import (
	"fmt"
	"strings"
	"time"
)

func cmdStatus(_ []string) error {
	snap, err := fetchLiveSnapshot()
	if err != nil {
		printDisconnectedStatus()
		return nil
	}
	if snap.Status == "" {
		printDisconnectedStatus()
		return nil
	}

	relayState := "Disconnected"
	if snap.RelayConnected {
		relayState = "Connected"
	}
	controlState := "DOWN"
	if snap.ControlOK {
		controlState = "OK"
	}
	statusLine := snap.Status
	if snap.Status == "CONNECTED" {
		if snap.UsingRelay {
			statusLine = "CONNECTED (Relay fallback)"
		} else {
			statusLine = "CONNECTED (Tunnel active)"
		}
	}

	fmt.Printf("Scale VPN Client (%s)\n", Version)
	fmt.Println("--------------------------------------------------")
	fmt.Printf("Status:           %s\n", statusLine)
	fmt.Printf("Interface:        %s\n", dash(snap.Interface))
	fmt.Printf("Overlay IP:       %s\n", dash(snap.OverlayIP))
	fmt.Printf("Public Key:       %s\n", shortKey(snap.PublicKey))
	fmt.Printf("Control Server:   %s (%s)\n", dash(redactURL(snap.ControlServer)), controlState)
	fmt.Printf("Relay Server:     %s (%s)\n", dash(redactURL(snap.RelayServer)), relayState)
	fmt.Printf("NAT Type:         %s\n", dash(snap.NATType))
	fmt.Printf("Active Peers:     %d online\n", snap.ActivePeers)
	return nil
}

func printDisconnectedStatus() {
	fmt.Printf("Scale VPN Client (%s)\n", Version)
	fmt.Println("--------------------------------------------------")
	fmt.Println("Status:           DISCONNECTED")
	fmt.Println("Interface:        -")
	fmt.Println("Overlay IP:       -")
	fmt.Println("Public Key:       -")
	fmt.Println("Control Server:   -")
	fmt.Println("Relay Server:     -")
	fmt.Println("NAT Type:         -")
	fmt.Println("Active Peers:     0 online")
}

func cmdPeers(_ []string) error {
	snap, err := fetchLiveSnapshot()
	if err != nil || snap.Status == "" || snap.Status == "DISCONNECTED" {
		fmt.Println("Scale VPN is not running. Start it with 'sudo scale up'.")
		return nil
	}

	fmt.Printf("%-14s %-13s %-16s %-12s %s\n", "PEER IP", "PUBLIC KEY", "TRANSPORT", "LAST PONG", "STATUS")
	if len(snap.Peers) == 0 {
		fmt.Println("(no peers)")
		return nil
	}
	for _, p := range snap.Peers {
		fmt.Printf("%-14s %-13s %-16s %-12s %s\n",
			dash(overlayIPOnly(p.OverlayIP)),
			shortKey(p.PublicKey),
			dash(p.Transport),
			ago(p.LastPong),
			dash(p.Status),
		)
	}
	return nil
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func overlayIPOnly(s string) string {
	return strings.Split(s, "/")[0]
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Round(time.Second)
	if d < time.Second {
		return "0s ago"
	}
	return d.String() + " ago"
}
