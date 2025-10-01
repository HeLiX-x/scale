package main

import (
	"fmt"
	"log"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// syncWireGuardPeers uses the wgctrl library to efficiently update the peers
// on a live WireGuard interface, applying all changes in a single operation.
func syncWireGuardPeers(interfaceName string, serverPeers []PeerConfig) error {
	// Establish a direct connection to the WireGuard kernel module.
	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %w", err)
	}
	defer wgClient.Close()

	// Get the current state of the specified WireGuard interface (e.g., "netcafe").
	device, err := wgClient.Device(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get device %s: %w", interfaceName, err)
	}

	// 1. Build a map of the desired peer configuration from the server for easy lookup.
	// This map will represent the "source of truth" for what the configuration should be.
	serverPeerMap := make(map[wgtypes.Key]wgtypes.PeerConfig)
	for _, p := range serverPeers {
		pubKey, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			log.Printf("Skipping peer with invalid public key %s: %v", p.PublicKey, err)
			continue
		}

		// Parse all allowed IPs for the peer.
		var allowedIPs []net.IPNet
		for _, ipStr := range p.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				log.Printf("Skipping invalid CIDR %s for peer %s: %v", ipStr, pubKey, err)
				continue
			}
			allowedIPs = append(allowedIPs, *ipNet)
		}

		// Resolve the peer's endpoint address if it exists.
		var endpoint *net.UDPAddr
		if p.Endpoint != "" {
			endpoint, err = net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				log.Printf("Skipping invalid endpoint %s for peer %s: %v", p.Endpoint, pubKey, err)
				continue
			}
		}

		serverPeerMap[pubKey] = wgtypes.PeerConfig{
			PublicKey:  pubKey,
			AllowedIPs: allowedIPs,
			Endpoint:   endpoint,
		}
	}

	// 2. Identify stale peers on the local device that are no longer present on the server.
	// These peers need to be removed from the local configuration.
	peersToRemove := []wgtypes.PeerConfig{}
	for _, existingPeer := range device.Peers {
		if _, found := serverPeerMap[existingPeer.PublicKey]; !found {
			log.Printf("Removing stale peer: %s", existingPeer.PublicKey)
			peersToRemove = append(peersToRemove, wgtypes.PeerConfig{
				PublicKey: existingPeer.PublicKey,
				Remove:    true, // This flag marks the peer for removal.
			})
		}
	}

	// 3. Combine the list of new/updated peers from the server and the list of stale peers
	// into a single configuration list that will be applied at once.
	finalPeerConfig := []wgtypes.PeerConfig{}
	for _, peer := range serverPeerMap {
		finalPeerConfig = append(finalPeerConfig, peer)
	}
	finalPeerConfig = append(finalPeerConfig, peersToRemove...)

	// 4. Apply the entire configuration in one atomic and efficient operation.
	// This single API call to the kernel is what makes this method so performant.
	//
	err = wgClient.ConfigureDevice(interfaceName, wgtypes.Config{
		Peers: finalPeerConfig,
	})

	if err != nil {
		return fmt.Errorf("failed to configure device: %w", err)
	}

	log.Println("Successfully synced WireGuard peers.")
	return nil
}
