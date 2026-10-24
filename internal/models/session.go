package models

import (
	"time"

	"github.com/google/uuid"
)

// DeviceSession tracks active phones where an employee account is logged in.
type DeviceSession struct {
	ID               uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID           uuid.UUID `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE" json:"user_id"`
	DeviceHardwareID string    `gorm:"type:varchar(150);not null;default:'unknown'" json:"device_hardware_id"`
	DeviceBrand      string    `gorm:"type:varchar(80);not null;default:'unknown'" json:"device_brand"`
	DeviceModel      string    `gorm:"type:varchar(120);not null;default:'unknown'" json:"device_model"`
	OSVersion        string    `gorm:"type:varchar(50);not null;default:'unknown'" json:"os_version"`
	RefreshTokenHash string    `gorm:"type:text;not null;default:''" json:"-"`
	FCMToken         *string   `gorm:"type:text" json:"fcm_token,omitempty"`
	LastActiveAt     time.Time `gorm:"not null;default:now()" json:"last_active_at"`
	CreatedAt        time.Time `gorm:"not null;default:now()" json:"created_at"`
}
