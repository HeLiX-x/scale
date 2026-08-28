package main

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"scale/authentication/controllers"
	"scale/authentication/routes"
	"scale/database"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

const allDevicesCacheKey = "cache:all_devices"

const deviceCacheUpdateInterval = 10 * time.Second

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	database.Connect()

	database.ConnectRedis()

	controllers.InitIPAllocator()

	refreshDeviceCache()

	go func() {
		ticker := time.NewTicker(deviceCacheUpdateInterval)
		defer ticker.Stop()
		for range ticker.C {
			refreshDeviceCache()
		}
	}()

	app := fiber.New()

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is not set in the environment")
	}

	deviceSecret := os.Getenv("DEVICE_AUTH_SECRET")
	if deviceSecret == "" {
		log.Fatal("DEVICE_AUTH_SECRET is not set in the environment")
	}

	stunController := controllers.NewStunController(jwtSecret)

	routes.SetupRoutes(app, jwtSecret, deviceSecret, stunController)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s...", port)
	if err := app.ListenTLS(":"+port, "cert.pem", "key.pem"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func refreshDeviceCache() {
	log.Println("Updating device cache from PostgreSQL...")
	devices, err := database.GetAllDevices()
	if err != nil {
		log.Printf("Error fetching devices for cache update: %v", err)
		return
	}
	var data []byte
	if len(devices) > 0 {
		data, err = json.Marshal(devices)
		if err != nil {
			log.Printf("Error marshaling devices for cache: %v", err)
			return
		}
	} else {
		data = []byte("[]")
	}
	if err := database.Rdb.Set(database.Ctx, allDevicesCacheKey, data, 0).Err(); err != nil {
		log.Printf("Error setting device cache in Redis: %v", err)
	}
}
