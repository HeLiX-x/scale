package middleware

import (
	"net/http"
	"scale/domain"
	"scale/internal/util"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func JwtAuthMiddleware(secret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(http.StatusUnauthorized).JSON(domain.ErrorResponse{Message: "Missing authorization header"})
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(http.StatusUnauthorized).JSON(domain.ErrorResponse{Message: "Authorization header format must be Bearer {token}"})
		}

		token := parts[1]
		// 2. Call functions using the correct package name 'util'.
		authorized, err := util.IsAuthorized(token, secret)
		if err != nil || !authorized {
			return c.Status(http.StatusUnauthorized).JSON(domain.ErrorResponse{Message: "Not authorized or invalid token"})
		}

		// 3. Call functions using the correct package name 'util'.
		userID, err := util.ExtractIDFromToken(token, secret)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(domain.ErrorResponse{Message: "Could not extract user from token"})
		}

		// Store user ID in Locals for handlers to access
		c.Locals("x-user-id", userID)

		return c.Next()
	}
}
