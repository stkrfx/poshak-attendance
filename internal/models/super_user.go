package models

import (
	"time"

	"github.com/google/uuid"
)

// SuperUser stores Admin and Developer accounts in a separate table from shop employees.
type SuperUser struct {
	ID             uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	FullName       string    `gorm:"type:varchar(120);not null" json:"full_name"`
	Email          string    `gorm:"type:varchar(150);uniqueIndex;not null" json:"email"`
	MobileNumber   string    `gorm:"type:varchar(20);uniqueIndex;not null" json:"mobile_number"`
	PasswordHash   string    `gorm:"type:text;not null" json:"-"`
	PrivilegeLevel string    `gorm:"type:varchar(20);not null" json:"privilege_level"` // "ADMIN" or "DEVELOPER"
	CreatedAt      time.Time `gorm:"not null;default:now()" json:"created_at"`
}
