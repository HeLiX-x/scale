package models

import (
	"gorm.io/gorm"
)

// User represents a user account in the system.
type User struct {
	gorm.Model
	Name         string `gorm:"not null"`
	Email        string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`

	// This field is for receiving the password during registration/login,
	// but it is NEVER saved to the database.
	Password string `gorm:"-"`
}
