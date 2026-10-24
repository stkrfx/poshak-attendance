package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a retail shop employee.
// Admin and Developer accounts are stored separately in SuperUser.
// Optional/nullable fields use omitempty so blank values are never sent in JSON payloads.
// Booleans do NOT use omitempty so false is always explicitly serialized.
type User struct {
	ID                  uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Name                string    `gorm:"type:varchar(120);uniqueIndex;not null" json:"name"`
	Username            string    `gorm:"type:varchar(80);uniqueIndex;not null" json:"username"`
	MobileNumber        string    `gorm:"type:varchar(20);uniqueIndex;not null" json:"mobile_number"`
	Gender              string    `gorm:"type:varchar(20);not null" json:"gender"`
	PasswordHash        string    `gorm:"type:text;not null" json:"-"`
	DOB                 *string   `gorm:"type:varchar(10)" json:"dob,omitempty"`
	IsDOBLocked         bool      `gorm:"not null;default:false" json:"is_dob_locked"`
	Email               *string   `gorm:"type:varchar(150);uniqueIndex" json:"email,omitempty"`
	Address             *string   `gorm:"type:text" json:"address,omitempty"`
	AvatarURL           *string   `gorm:"type:text" json:"avatar_url,omitempty"`
	CanEditUsername     bool      `gorm:"not null;default:true" json:"can_edit_username"`
	CanUploadDocuments  bool      `gorm:"not null;default:true" json:"can_upload_documents"`
	IsBlocked           bool      `gorm:"not null;default:false" json:"is_blocked"`
	BlockedReason       *string   `gorm:"type:text" json:"blocked_reason,omitempty"`
	CreatedAt           time.Time `gorm:"not null;default:now()" json:"created_at"`
	UpdatedAt           time.Time `gorm:"not null;default:now()" json:"updated_at"`
}
