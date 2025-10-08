package database

import "scale/models"

// FindDeviceByPublicKey retrieves a device from the database by its WireGuard public key.
func FindDeviceByPublicKey(publicKey string) (*models.Device, error) {
	var device models.Device
	result := DB.Where("public_key = ?", publicKey).First(&device)
	return &device, result.Error
}

// CreateDevice saves a new device record to the database.
func CreateDevice(device *models.Device) error {
	result := DB.Create(device)
	return result.Error
}

// UpdateDevice updates an existing device's information.
func UpdateDevice(device *models.Device) error {
	result := DB.Save(device)
	return result.Error
}

// GetActivePeersExcept retrieves all devices except for the one with the given public key.
// This is used to build the peer list for a client.
func GetActivePeersExcept(publicKey string) ([]models.Device, error) {
	var devices []models.Device
	result := DB.Where("public_key <> ?", publicKey).Find(&devices)
	return devices, result.Error
}

func GetAllDevices() ([]models.Device, error) {
	var devices []models.Device
	result := DB.Find(&devices)
	return devices, result.Error
}
