package controllers

import (
	"fmt"
	"net/http"
	"scale/authentication/models"
	"scale/database"

	"github.com/gofiber/fiber/v2"
)

// RegisterDeviceRequest defines the expected payload for device registration
type RegisterDeviceRequest struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint,omitempty"`
}

// HeartbeatRequest defines the payload for the heartbeat endpoint
type HeartbeatRequest struct {
	DeviceID string `json:"device_id"`
	Endpoint string `json:"endpoint"`
}

// PeerConfig defines the WireGuard peer information returned to clients
type PeerConfig struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

func ListPeers(c *fiber.Ctx) error {
	// The auth middleware places the user/device ID into c.Locals
	requestingDeviceID, ok := c.Locals("x-user-id").(string)
	if !ok || requestingDeviceID == "" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or missing user ID in token"})
	}

	peers, err := database.GetActivePeersExcept(requestingDeviceID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve peers"})
	}

	peerConfigs := make([]PeerConfig, 0, len(peers))
	for _, peer := range peers {
		peerConfigs = append(peerConfigs, PeerConfig{
			PublicKey:  peer.PublicKey,
			AllowedIPs: []string{fmt.Sprintf("%s/32", peer.AssignedIP)},
			Endpoint:   peer.Endpoint,
		})
	}

	return c.JSON(peerConfigs)
}

// RegisterDevice handles WireGuard device registration and updates
func RegisterDevice(c *fiber.Ctx) error {
	var req RegisterDeviceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Note: You will need to implement the database functions like FindDeviceByID, CreateDevice etc.
	device, err := database.FindDeviceByID(req.DeviceID)
	if err != nil {
		// This is just an example of handling a "not found" case to create a new device
		// Your actual implementation might differ
		if err.Error() == "record not found" {
			ip, err := utils.IPAllocator.AllocateIP() // You need to implement the IPAllocator
			if err != nil {
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "IP allocation failed"})
			}

			newDevice := &models.Device{ // Make sure you have a Device model in your models package
				ID:         req.DeviceID,
				PublicKey:  req.PublicKey,
				AssignedIP: ip,
				Endpoint:   req.Endpoint,
			}

			if err := database.CreateDevice(newDevice); err != nil {
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create device"})
			}
			// Return the newly created device's info
			return c.JSON(fiber.Map{
				"assigned_ip": newDevice.AssignedIP,
				"message":     "Registration successful",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Database error on find"})
	}

	// If device exists, update it
	device.PublicKey = req.PublicKey
	device.Endpoint = req.Endpoint
	if err := database.UpdateDevice(device); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update device"})
	}

	return c.JSON(fiber.Map{
		"assigned_ip": device.AssignedIP,
		"message":     "Device details updated successfully",
	})
}

// GetPeerConfig returns WireGuard peer configurations for the device
func GetPeerConfig(c *fiber.Ctx) error {
	deviceID := c.Params("device_id")

	device, err := database.FindDeviceByID(deviceID)
	if err != nil || device == nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Device not found"})
	}

	peers, err := database.GetActivePeersExcept(deviceID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve peers"})
	}

	peerConfigs := make([]PeerConfig, 0, len(peers))
	for _, peer := range peers {
		peerConfigs = append(peerConfigs, PeerConfig{
			PublicKey:  peer.PublicKey,
			AllowedIPs: []string{peer.AssignedIP + "/32"},
			Endpoint:   peer.Endpoint,
		})
	}

	return c.JSON(fiber.Map{
		"device_ip":    device.AssignedIP,
		"peer_configs": peerConfigs,
	})
}

// Heartbeat handles updates to a device's endpoint for NAT traversal
func Heartbeat(c *fiber.Ctx) error {
	var req HeartbeatRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.DeviceID == "" || req.Endpoint == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "DeviceID and Endpoint are required"})
	}

	device, err := database.FindDeviceByID(req.DeviceID)
	if err != nil || device == nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Device not found"})
	}

	device.Endpoint = req.Endpoint
	if err := database.UpdateDevice(device); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update device endpoint"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Heartbeat received"})
}
