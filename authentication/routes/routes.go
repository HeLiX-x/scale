package routes

import (
	authControllers "scale/authentication/controllers"
	device_controller "scale/authentication/controllers"
	"scale/authentication/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App, jwtSecret string, deviceSecret string) {
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Hello from Scale API!",
		})
	})

	app.Post("/api/register", authControllers.Register)
	app.Post("/api/login", authControllers.Login)

	// Protect routes with middleware
	app.Get("/api/user", middleware.JwtAuthMiddleware(jwtSecret), authControllers.User)
	app.Post("/api/logout", middleware.JwtAuthMiddleware(jwtSecret), authControllers.Logout)

	// Device registration and peer config routes
	app.Post("/api/devices/register", middleware.JwtAuthMiddleware(jwtSecret), device_controller.RegisterDevice)
	app.Get("/api/devices/:device_id/peers", middleware.JwtAuthMiddleware(jwtSecret), device_controller.GetPeerConfig)
	app.Post("/api/devices/heartbeat", middleware.JwtAuthMiddleware(jwtSecret), device_controller.Heartbeat)
	app.Get("/api/devices/:device_id/peers", middleware.JwtAuthMiddleware(jwtSecret), device_controller.GetPeerConfig)

}
