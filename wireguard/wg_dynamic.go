package main

import (
	"fmt"
	"log"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// syncWireGuardPeers - MODIFIED to accept ReplacePeers flag
// If replacePeers is false, it only adds/updates the peers listed, leaving others untouched.
// If replacePeers is true, it removes any existing peers not in the provided list.
func syncWireGuardPeers(interfaceName string, serverPeers []PeerConfig, replacePeers bool) error {
	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %w", err)
	}
	defer wgClient.Close()

	currentDevice, err := wgClient.Device(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device %s: %w", interfaceName, err)
	}

	targetPeerConfigs := []wgtypes.PeerConfig{}
	serverPeerMap := make(map[wgtypes.Key]bool) // Track keys provided by server

	for _, p := range serverPeers {
		pubKey, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			log.Printf("Skipping peer with invalid public key %s: %v", p.PublicKey, err)
			continue
		}
		serverPeerMap[pubKey] = true // Mark this key as present

		var allowedIPs []net.IPNet
		for _, ipStr := range p.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				log.Printf("Skipping invalid CIDR %s for peer %s: %v", ipStr, pubKey.String()[:8], err)
				continue
			}
			allowedIPs = append(allowedIPs, *ipNet)
		}

		// Endpoint is NOT resolved here anymore. It's set by updateWireguardPeerEndpoint
		// However, if an Endpoint string IS provided (e.g., from server default), parse it.
		var endpointAddr *net.UDPAddr
		if p.Endpoint != "" {
			endpointAddr, err = net.ResolveUDPAddr("udp", p.Endpoint)
			// Log error but don't skip peer entirely if endpoint invalid, WG might use last known good one
			if err != nil {
				log.Printf("Warning: Invalid endpoint format '%s' for peer %s: %v", p.Endpoint, pubKey.String()[:8], err)
			}
		}

		targetPeerConfigs = append(targetPeerConfigs, wgtypes.PeerConfig{
			PublicKey:  pubKey,
			AllowedIPs: allowedIPs,
			Endpoint:   endpointAddr, // Use parsed endpoint if provided
			// UpdateOnly: !replacePeers, // This flag might be useful but requires careful testing
		})
	}

	// If replacing peers, figure out which ones to remove
	if replacePeers {
		for _, existingPeer := range currentDevice.Peers {
			if _, found := serverPeerMap[existingPeer.PublicKey]; !found {
				log.Printf("Removing stale peer (ReplacePeers=true): %s", existingPeer.PublicKey.String()[:8])
				targetPeerConfigs = append(targetPeerConfigs, wgtypes.PeerConfig{
					PublicKey: existingPeer.PublicKey,
					Remove:    true,
				})
			}
		}
	}

	// Apply the configuration
	err = wgClient.ConfigureDevice(interfaceName, wgtypes.Config{
		Peers:        targetPeerConfigs,
		ReplacePeers: replacePeers, // Use the flag here
	})

	if err != nil {
		return fmt.Errorf("failed to configure device %s: %w", interfaceName, err)
	}

	if replacePeers {
		log.Printf("Successfully synced WireGuard peers (ReplacePeers=true) for %s.", interfaceName)
	} else {
		log.Printf("Successfully updated WireGuard peers (ReplacePeers=false) for %s.", interfaceName)
	}
	return nil
}

// --- NEW: Function to update only the endpoint for a specific peer ---
func updateWireguardPeerEndpoint(interfaceName string, peerKey wgtypes.Key, endpoint *net.UDPAddr) error {
	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %w", err)
	}
	defer wgClient.Close()

	peerConfig := wgtypes.PeerConfig{
		PublicKey:  peerKey,
		UpdateOnly: true,     // IMPORTANT: Only update existing peer
		Endpoint:   endpoint, // Set the new endpoint (can be nil to clear)
	}

	err = wgClient.ConfigureDevice(interfaceName, wgtypes.Config{
		Peers:        []wgtypes.PeerConfig{peerConfig},
		ReplacePeers: false, // IMPORTANT: Do not remove other peers
	})

	if err != nil {
		return fmt.Errorf("failed to update endpoint for peer %s on %s: %w", peerKey.String()[:8], interfaceName, err)
	}

	if endpoint != nil {
		log.Printf("WireGuard endpoint for peer %s updated to %s", peerKey.String()[:8], endpoint.String())
	} else {
		log.Printf("WireGuard endpoint for peer %s cleared.", peerKey.String()[:8])
	}
	return nil
}
