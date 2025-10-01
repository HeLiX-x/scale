package middleware

import (
	"net/http"
	"scale/domain"
	"scale/internal/tokenutil"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func JwtAuthMiddleware(secret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 {
			return c.Status(http.StatusUnauthorized).JSON(domain.ErrorResponse{Message: "Authorization header missing or malformed"})
		}

		token := parts[1]
		authorized, err := tokenutil.IsAuthorized(token, secret)
		if err != nil || !authorized {
			return c.Status(http.StatusUnauthorized).JSON(domain.ErrorResponse{Message: "Not authorized"})
		}

		userID, err := tokenutil.ExtractIDFromToken(token, secret)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(domain.ErrorResponse{Message: err.Error()})
		}

		// Store user ID in Locals for handlers to access
		c.Locals("x-user-id", userID)

		return c.Next()
	}
}
