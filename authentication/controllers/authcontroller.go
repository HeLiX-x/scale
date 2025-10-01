package controllers

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"scale/database" // Corrected import path
	"scale/models"   // Correctly imports from the central models package
)

// JWT Secret Key (in production, load from env/config)
var secretKey = "your-secret-key"

func Hello(c *fiber.Ctx) error {
	return c.SendString("Hello, world!")
}

// Register handles user registration
func Register(c *fiber.Ctx) error {
	fmt.Println("Received a registration request")

	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Failed to parse request body"})
	}

	// Check if email already exists, and handle potential database errors.
	var existingUser models.User
	err := database.DB.Where("email = ?", data["email"]).First(&existingUser).Error
	if err == nil {
		// If err is nil, a user was found.
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Email already exists"})
	} else if err != gorm.ErrRecordNotFound {
		// If the error is something other than "not found", it's a real database issue.
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error on user lookup"})
	}
	// If the error IS gorm.ErrRecordNotFound, we can safely proceed.

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data["password"]), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	// Create new user, storing the hash in the correct field
	user := models.User{
		Name:         data["name"],
		Email:        data["email"],
		PasswordHash: string(hashedPassword), // Correctly uses PasswordHash
	}

	// Save user in database
	if err := database.DB.Create(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create user"})
	}

	return c.JSON(fiber.Map{"message": "User registered successfully"})
}

// Login handles user login and JWT token creation
func Login(c *fiber.Ctx) error {
	fmt.Println("Received a login request")

	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Failed to parse request body"})
	}

	// Check if user exists
	var user models.User
	if err := database.DB.Where("email = ?", data["email"]).First(&user).Error; err != nil {
		fmt.Println("User not found")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Invalid credentials"})
	}

	// Compare passwords against the stored hash
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(data["password"])); err != nil {
		fmt.Println("Invalid password")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Invalid credentials"})
	}

	// Generate JWT token
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": strconv.Itoa(int(user.ID)),
		"exp": time.Now().Add(time.Hour * 24).Unix(), // Expires in 24 hours
	})

	token, err := claims.SignedString([]byte(secretKey))
	if err != nil {
		fmt.Println("Error generating token:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	// Set JWT token in cookie
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
		Secure:   true,
	}
	c.Cookie(&cookie)

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"message": "Login successful"})
}

// User retrieves user info based on JWT in cookie
func User(c *fiber.Ctx) error {
	fmt.Println("Request to get user info")

	cookie := c.Cookies("jwt")

	token, err := jwt.ParseWithClaims(cookie, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to parse claims"})
	}

	id, err := strconv.Atoi(fmt.Sprintf("%v", claims["sub"]))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid token subject"})
	}

	// Fetch user from DB
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	return c.JSON(user)
}

// Logout clears the JWT token from cookies
func Logout(c *fiber.Ctx) error {
	fmt.Println("Received a logout request")

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   true,
	}
	c.Cookie(&cookie)

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"message": "Logout successful"})
}
