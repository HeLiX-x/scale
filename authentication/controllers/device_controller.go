package controllers

import (
	"log"
	"net/http"
	"scale/database"
	"scale/ipmanager" // Assuming you have an IP allocator
	"scale/models"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// A simple in-memory IP allocator for demonstration.
// In a real application, this might also be stored in the database.
var ipAllocator, _ = ipmanager.NewIPAllocator("100.64.0.0/24", nil)

type RegisterDeviceRequest struct {
	PublicKey string `json:"public_key"`
	// UserID is needed to associate the device with a user.
	// This would typically come from the JWT claims.
	UserID uint `json:"user_id"`
}

type HeartbeatRequest struct {
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
}

type PeerConfig struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

// RegisterDevice now handles device registration with a real database.
func RegisterDevice(c *fiber.Ctx) error {
	var req RegisterDeviceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Check if device already exists.
	device, err := database.FindDeviceByPublicKey(req.PublicKey)
	if err != nil {
		// If the error is "record not found", we create a new device.
		if err == gorm.ErrRecordNotFound {
			log.Printf("Registering new device with public key: %s", req.PublicKey)

			// Allocate a new IP address. We use /32 for a single host.
			ip, err := ipAllocator.AllocateCIDR(32)
			if err != nil {
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "IP allocation failed"})
			}

			newDevice := &models.Device{
				PublicKey:  req.PublicKey,
				AssignedIP: ip,
				UserID:     req.UserID, // Associate with the user.
			}

			if err := database.CreateDevice(newDevice); err != nil {
				// If creation fails, release the IP.
				ipAllocator.ReleaseCIDR(ip)
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create device"})
			}
			return c.JSON(fiber.Map{
				"assigned_ip": newDevice.AssignedIP,
				"message":     "Registration successful",
			})
		}
		// For other database errors, return a server error.
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	// If the device exists, we can simply return its info.
	// You might add logic here to update its endpoint if provided.
	log.Printf("Device with public key %s already registered.", req.PublicKey)
	return c.JSON(fiber.Map{
		"assigned_ip": device.AssignedIP,
		"message":     "Device already registered",
	})
}

// GetPeerConfig now fetches real peers from the database.
func GetPeerConfig(c *fiber.Ctx) error {
	// The client's public key should be passed as a parameter.
	clientPubKey := c.Params("publicKey")
	if clientPubKey == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Device public key is required"})
	}

	peers, err := database.GetActivePeersExcept(clientPubKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve peers"})
	}

	peerConfigs := make([]PeerConfig, len(peers))
	for i, peer := range peers {
		peerConfigs[i] = PeerConfig{
			PublicKey:  peer.PublicKey,
			AllowedIPs: []string{peer.AssignedIP}, // The IP itself implies /32
			Endpoint:   peer.Endpoint,
		}
	}

	return c.JSON(fiber.Map{
		"peer_configs": peerConfigs,
	})
}

// Heartbeat now updates a device's endpoint in the database.
func Heartbeat(c *fiber.Ctx) error {
	var req HeartbeatRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	device, err := database.FindDeviceByPublicKey(req.PublicKey)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Device not found"})
	}

	device.Endpoint = req.Endpoint
	if err := database.UpdateDevice(device); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update device endpoint"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Heartbeat received"})
}
