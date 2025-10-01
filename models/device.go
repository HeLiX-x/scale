package models

import (
	"gorm.io/gorm"
)

type Device struct {
	gorm.Model
	PublicKey  string `gorm:"uniqueIndex;not null"`
	AssignedIP string `gorm:"uniqueIndex;not null"`
	Endpoint   string
	UserID     uint
}
