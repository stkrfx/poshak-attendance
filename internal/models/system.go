package models

import (
	"time"

	"github.com/google/uuid"
)

// Notification stores targeted user alerts or global broadcast messages.
type Notification struct {
	ID        uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID    *uuid.UUID `gorm:"type:uuid;index" json:"user_id,omitempty"` // Null means global broadcast to all employees
	Title     string     `gorm:"type:varchar(150);not null" json:"title"`
	Body      string     `gorm:"type:text;not null" json:"body"`
	IsRead    bool       `gorm:"not null;default:false" json:"is_read"`
	CreatedAt time.Time  `gorm:"not null;default:now()" json:"created_at"`
}

// AppRelease tracks Android APK versions for the Force Update gate.
type AppRelease struct {
	ID             uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	VersionName    string    `gorm:"type:varchar(30);not null" json:"version_name"`
	VersionCode    int       `gorm:"not null;uniqueIndex" json:"version_code"`
	APKDownloadURL string    `gorm:"type:text;not null" json:"apk_download_url"`
	ReleaseNotes   string    `gorm:"type:text;not null" json:"release_notes"`
	IsForceUpdate  bool      `gorm:"not null;default:true" json:"is_force_update"`
	CreatedAt      time.Time `gorm:"not null;default:now()" json:"created_at"`
}

// EmailOTP stores 6-digit OTP codes for email verification, password reset, and device logout confirmation.
type EmailOTP struct {
	ID        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Email     string    `gorm:"type:varchar(150);not null;index" json:"email"`
	OTPCode   string    `gorm:"type:varchar(6);not null" json:"-"`
	Purpose   string    `gorm:"type:varchar(30);not null" json:"purpose"` // "VERIFY_EMAIL" or "RESET_PASSWORD"
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	CreatedAt time.Time `gorm:"not null;default:now()" json:"created_at"`
}
