package util

import (
	"fmt"
	models "scale/models" // 1. Import the central models package
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

// CreateAccessToken now correctly accepts a *models.User
func CreateAccessToken(user *models.User, secret string, expiry int) (accessToken string, err error) {
	expTime := time.Now().Add(time.Hour * time.Duration(expiry))

	// Convert the uint ID to a string for the JWT claim
	userIDStr := strconv.FormatUint(uint64(user.ID), 10)

	claims := &JwtCustomClaims{
		Name: user.Name,
		ID:   userIDStr, // Use the converted string ID
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return t, nil
}

// CreateRefreshToken now correctly accepts a *models.User
func CreateRefreshToken(user *models.User, secret string, expiry int) (refreshToken string, err error) {
	expTime := time.Now().Add(time.Hour * time.Duration(expiry))

	// Convert the uint ID to a string for the JWT claim
	userIDStr := strconv.FormatUint(uint64(user.ID), 10)

	claimsRefresh := &JwtCustomRefreshClaims{
		ID: userIDStr, // Use the converted string ID
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsRefresh)
	rt, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return rt, nil
}

func IsAuthorized(requestToken string, secret string) (bool, error) {
	_, err := jwt.Parse(requestToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func ExtractIDFromToken(requestToken string, secret string) (string, error) {
	token, err := jwt.Parse(requestToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid Token")
	}

	return claims["sub"].(string), nil
}
