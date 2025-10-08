package main

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"scale/authentication/routes"
	"scale/database"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

// The Redis key for the cached device list
const allDevicesCacheKey = "cache:all_devices"

// How often to update the cache from PostgreSQL
const deviceCacheUpdateInterval = 10 * time.Second

// This function runs in the background to keep the device cache fresh.
func updateDeviceCache() {
	// Create a ticker that fires every 10 seconds.
	ticker := time.NewTicker(deviceCacheUpdateInterval)
	defer ticker.Stop()

	for {
		<-ticker.C // Wait for the ticker to fire

		log.Println("Updating device cache from PostgreSQL...")

		// Fetch all devices from the primary database.
		devices, err := database.GetAllDevices()
		if err != nil {
			log.Printf("Error fetching devices for cache update: %v", err)
			continue // Skip this update if there's an error
		}

		// Serialize the device list into JSON format.
		// If there are no devices, we'll cache an empty list.
		var data []byte
		if len(devices) > 0 {
			data, err = json.Marshal(devices)
			if err != nil {
				log.Printf("Error marshaling devices for cache: %v", err)
				continue
			}
		} else {
			data = []byte("[]") // Cache an empty JSON array
		}

		// Store the JSON data in Redis. We don't set a TTL because this
		// goroutine is responsible for keeping it up-to-date.
		err = database.Rdb.Set(database.Ctx, allDevicesCacheKey, data, 0).Err()
		if err != nil {
			log.Printf("Error setting device cache in Redis: %v", err)
		}
	}
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Initialize the database connection on startup.
	database.Connect()

	database.ConnectRedis()

	go updateDeviceCache()

	app := fiber.New()

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is not set in the environment")
	}

	deviceSecret := os.Getenv("DEVICE_AUTH_SECRET")
	if deviceSecret == "" {
		log.Fatal("DEVICE_AUTH_SECRET is not set in the environment")
	}

	// Setup the routes, passing both secrets
	routes.SetupRoutes(app, jwtSecret, deviceSecret)

	log.Println("Starting server on port 8080...")
	if err := app.Listen(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
