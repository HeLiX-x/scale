package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Name  string `json:"name" gorm:"not null" binding:"required"`
	Email string `json:"email" gorm:"uniqueIndex;not null" binding:"required,email"`
}
