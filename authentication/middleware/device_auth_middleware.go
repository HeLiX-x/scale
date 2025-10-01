package middleware

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// DeviceAuthMiddleware creates a new middleware to authenticate devices using a pre-shared key.
func DeviceAuthMiddleware(secret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the token from the custom header
		token := c.Get("X-Auth-Token")

		// Check if the header is present and if the token matches the secret
		if token == "" || token != secret {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error": "Unauthorized: Invalid or missing device auth token",
			})
		}

		// If the token is valid, proceed to the next handler
		return c.Next()
	}
}
