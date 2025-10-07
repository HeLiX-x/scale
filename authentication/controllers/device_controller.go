package controllers

import (
	"log"
	"net/http"
	"scale/database"
	"scale/ipmanager"
	"scale/models"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

var ipAllocator, _ = ipmanager.NewIPAllocator("100.64.0.0/24")

// FIX: Removed UserID from the request body.
type RegisterDeviceRequest struct {
	PublicKey string `json:"public_key"`
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

func RegisterDevice(c *fiber.Ctx) error {
	var req RegisterDeviceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// FIX: Get the user ID securely from the middleware context.
	userIDStr, ok := c.Locals("x-user-id").(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Could not get user ID from token"})
	}
	// Convert the string ID to a uint.
	userID_64, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid user ID format in token"})
	}
	userID := uint(userID_64)

	device, err := database.FindDeviceByPublicKey(req.PublicKey)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			log.Printf("Registering new device with public key: %s", req.PublicKey)
			ip, err := ipAllocator.AllocateCIDR(32)
			if err != nil {
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "IP allocation failed"})
			}
			newDevice := &models.Device{
				PublicKey:  req.PublicKey,
				AssignedIP: ip,
				UserID:     userID, // FIX: Use the secure user ID from the token.
			}
			if err := database.CreateDevice(newDevice); err != nil {
				ipAllocator.ReleaseCIDR(ip)
				return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create device"})
			}
			return c.JSON(fiber.Map{
				"assigned_ip": newDevice.AssignedIP,
				"message":     "Registration successful",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	log.Printf("Device with public key %s already registered.", req.PublicKey)
	return c.JSON(fiber.Map{
		"assigned_ip": device.AssignedIP,
		"message":     "Device already registered",
	})
}

func GetPeerConfig(c *fiber.Ctx) error {
	clientPubKey := c.Params("device_id") // Use the correct parameter name
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
			AllowedIPs: []string{peer.AssignedIP},
			Endpoint:   peer.Endpoint,
		}
	}
	return c.JSON(fiber.Map{
		"peer_configs": peerConfigs,
	})
}

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
