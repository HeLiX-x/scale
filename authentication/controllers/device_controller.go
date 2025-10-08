package controllers

import (
	"fmt"
	"log"
	"net/http"
	"scale/database"
	"scale/ipmanager"
	"scale/models"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const deviceHeartbeatTTL = 90 * time.Second

var ipAllocator, _ = ipmanager.NewIPAllocator("100.64.0.0/24")

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

	userIDStr, ok := c.Locals("x-user-id").(string)
	if !ok {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Could not get user ID from token"})
	}
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
				UserID:     userID,
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

func Heartbeat(c *fiber.Ctx) error {
	var req HeartbeatRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	redisKey := fmt.Sprintf("device:endpoint:%s", req.PublicKey)

	err := database.Rdb.Set(database.Ctx, redisKey, req.Endpoint, deviceHeartbeatTTL).Err()
	if err != nil {
		log.Printf("Failed to set heartbeat in Redis for %s: %v", req.PublicKey, err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process heartbeat"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Heartbeat received"})
}

func GetPeerConfig(c *fiber.Ctx) error {
	clientPubKey := c.Params("device_id")
	if clientPubKey == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Device public key is required"})
	}

	peers, err := database.GetActivePeersExcept(clientPubKey)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve peers"})
	}

	peerConfigs := make([]PeerConfig, 0, len(peers))
	for _, peer := range peers {
		redisKey := fmt.Sprintf("device:endpoint:%s", peer.PublicKey)

		endpoint, err := database.Rdb.Get(database.Ctx, redisKey).Result()

		if err == redis.Nil {
			continue
		} else if err != nil {
			log.Printf("Could not get endpoint for peer %s from Redis: %v", peer.PublicKey, err)
			continue
		}

		peerConfigs = append(peerConfigs, PeerConfig{
			PublicKey:  peer.PublicKey,
			AllowedIPs: []string{peer.AssignedIP},
			Endpoint:   endpoint,
		})
	}

	return c.JSON(fiber.Map{
		"peer_configs": peerConfigs,
	})
}
