package database

import "time"

type User struct {
	ID           uint      `gorm:"primaryKey"`
	Username     string    `gorm:"uniqueIndex;not null"`
	Email        string    `gorm:"uniqueIndex;not null"`
	PasswordHash string    `gorm:"not null"`
	CreatedAt    time.Time `gorm:"default:now()"`
}

type IPPool struct {
	IP          string `gorm:"type:inet;primaryKey"`
	Allocated   bool   `gorm:"not null"`
	DeviceID    *uint
	AllocatedAt *time.Time
}

type PeerRelation struct {
	ID        uint      `gorm:"primaryKey"`
	DeviceID  uint      `gorm:"not null"`
	PeerID    uint      `gorm:"not null"`
	CreatedAt time.Time `gorm:"default:now()"`
}
