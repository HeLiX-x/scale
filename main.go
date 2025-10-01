package main

import (
	"log"
	"os"

	"scale/authentication/routes" // Using the routes we built
	// Assuming you have a database package
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Initialize the database connection
	// You will need to implement this function in your database package
	// database.Connect()

	app := fiber.New()

	// Get secrets from environment variables
	// Note: In production, you should handle missing secrets more gracefully
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
