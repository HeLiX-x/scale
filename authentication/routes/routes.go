package routes

import (
	authControllers "scale/authentication/controllers"
	device_controller "scale/authentication/controllers/device_controller"
	mainControllers "scale/controllers"
	"scale/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App, jwtSecret string) {
	app.Get("/", mainControllers.Hello)

	app.Post("/api/register", authControllers.Register)
	app.Post("/api/login", authControllers.Login)

	// Protect routes with middleware
	app.Get("/api/user", middleware.JwtAuthMiddleware(jwtSecret), authControllers.User)
	app.Post("/api/logout", middleware.JwtAuthMiddleware(jwtSecret), authControllers.Logout)

	// Device registration and peer config routes
	app.Post("/api/devices/register", middleware.JwtAuthMiddleware(jwtSecret), device_controller.RegisterDevice)
	app.Get("/api/devices/:device_id/peers", middleware.JwtAuthMiddleware(jwtSecret), device_controller.GetPeerConfig)

}
