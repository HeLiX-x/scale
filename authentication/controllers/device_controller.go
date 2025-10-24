package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"scale/database"
	"scale/ipmanager"
	"scale/models"
	"scale/pkg/types"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const deviceHeartbeatTTL = 90 * time.Second

var ipAllocator *ipmanager.IPAllocator

type RegisterDeviceRequest struct {
	PublicKey string `json:"public_key"`
}

type HeartbeatRequest struct {
	SrflxEndpoint *types.Endpoint  `json:"srflx_endpoint"`
	HostEndpoints []types.Endpoint `json:"host_endpoints"`
}

type PeerConfig struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

func InitIPAllocator() {
	var err error
	ipAllocator, err = ipmanager.NewIPAllocator("100.64.0.0/24")
	if err != nil {
		log.Fatalf("Failed to initialize IP allocator: %v", err)
	}
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

	// GET THE PUBLIC KEY FROM THE HEADER (client is already sending it)
	clientPubKey := c.Get("X-Device-Public-Key")
	if clientPubKey == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Missing X-Device-Public-Key header"})
	}

	redisKey := fmt.Sprintf("device:endpoints:%s", clientPubKey) // <-- Use a new key name

	// Combine all endpoints into one list
	allEndpoints := req.HostEndpoints
	if req.SrflxEndpoint != nil {
		allEndpoints = append(allEndpoints, *req.SrflxEndpoint)
	}

	if len(allEndpoints) == 0 {
		// No endpoints, maybe just clear the key?
		database.Rdb.Del(database.Ctx, redisKey)
		return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Heartbeat received (no endpoints)"})
	}

	// Serialize the list of endpoints to JSON
	endpointsJSON, err := json.Marshal(allEndpoints)
	if err != nil {
		log.Printf("Failed to marshal endpoints for %s: %v", clientPubKey, err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process endpoints"})
	}

	// Store the JSON string in Redis
	err = database.Rdb.Set(database.Ctx, redisKey, string(endpointsJSON), deviceHeartbeatTTL).Err()
	if err != nil {
		log.Printf("Failed to set heartbeat in Redis for %s: %v", clientPubKey, err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process heartbeat"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Heartbeat received"})
}

func GetPeerConfig(c *fiber.Ctx) error {
	clientPubKey := c.Params("device_id")
	if clientPubKey == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Device public key is required"})
	}

	// **CHANGE**: Step 1 - Fetch the device list from the Redis cache.
	cachedDevicesJSON, err := database.Rdb.Get(database.Ctx, "cache:all_devices").Result()
	if err != nil {
		// If the cache is empty for some reason, return an error.
		// This should be rare as the background worker keeps it populated.
		log.Printf("Device cache is not available: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve peer list from cache"})
	}

	// **CHANGE**: Step 2 - Deserialize the JSON and filter out the current client.
	var allDevices []models.Device
	if err := json.Unmarshal([]byte(cachedDevicesJSON), &allDevices); err != nil {
		log.Printf("Failed to unmarshal cached devices: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to parse peer list"})
	}

	peers := make([]models.Device, 0, len(allDevices))
	for _, device := range allDevices {
		if device.PublicKey != clientPubKey {
			peers = append(peers, device)
		}
	}

	// **NO CHANGE**: Step 3 - The logic to check for online peers remains the same.
	// We still check for live endpoints for each peer from the cached list.
	peerConfigs := make([]PeerConfig, 0, len(peers))
	for _, peer := range peers {
		redisKey := fmt.Sprintf("device:endpoint:%s", peer.PublicKey)
		endpoint, err := database.Rdb.Get(database.Ctx, redisKey).Result()
		if err == redis.Nil {
			continue // Peer is offline
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
