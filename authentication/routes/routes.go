package routes

import (
	"scale/authentication/controllers" // <-- 1. CLEANED UP: Single import for all controllers.
	"scale/authentication/middleware"

	"github.com/gofiber/fiber/v2"
)

// 2. UPDATED: The function now accepts the StunController instance as a parameter.
func SetupRoutes(app *fiber.App, jwtSecret string, deviceSecret string, stunController *controllers.StunController) {
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Hello from Scale API!",
		})
	})

	// Use the single 'controllers' package for all handlers
	app.Post("/api/register", controllers.Register)
	app.Post("/api/login", controllers.Login)

	// Protect routes with middleware
	app.Get("/api/user", middleware.JwtAuthMiddleware(jwtSecret), controllers.User)
	app.Post("/api/logout", middleware.JwtAuthMiddleware(jwtSecret), controllers.Logout)

	// Device registration and peer config routes
	app.Post("/api/devices/register", middleware.JwtAuthMiddleware(jwtSecret), controllers.RegisterDevice)
	app.Post("/api/devices/heartbeat", middleware.JwtAuthMiddleware(jwtSecret), controllers.Heartbeat)

	// 4. CLEANED UP: Removed the duplicate route definition.
	app.Get("/api/devices/:device_id/peers", middleware.JwtAuthMiddleware(jwtSecret), controllers.GetPeerConfig)

	// 3. FIXED: These now correctly use the 'stunController' variable passed into the function.
	app.Get("/api/poll", middleware.JwtAuthMiddleware(jwtSecret), stunController.Poll)
	app.Get("/api/stun", stunController.HandleStunRequest)
}
