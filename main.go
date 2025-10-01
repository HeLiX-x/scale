package main

import (
	"log"
	"os"

	"scale/authentication/routes"
	"scale/database"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Initialize the database connection on startup.
	database.Connect()

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
