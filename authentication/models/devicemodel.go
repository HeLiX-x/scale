package models

type Device struct {
	ID         string `gorm:"primaryKey"`
	PublicKey  string `gorm:"not null"`
	AssignedIP string `gorm:"unique;not null"`
	Endpoint   string
}
