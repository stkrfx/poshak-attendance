package models

import (
	"time"

	"github.com/google/uuid"
)

// UserDocument stores Identity Documents and Educational Certificates uploaded by an employee.
type UserDocument struct {
	ID              uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID          uuid.UUID `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE" json:"user_id"`
	Category        string    `gorm:"type:varchar(30);not null" json:"category"`      // "IDENTITY" or "CERTIFICATE"
	DocumentType    string    `gorm:"type:varchar(50);not null" json:"document_type"` // e.g., "PAN", "VOTER_ID", "DRIVING_LICENSE", "MATRICULATION", etc.
	DocumentNumber  string    `gorm:"type:varchar(100);not null" json:"document_number"`
	InstitutionName *string   `gorm:"type:varchar(200)" json:"institution_name,omitempty"`
	StartDate       *string   `gorm:"type:varchar(10)" json:"start_date,omitempty"`
	EndDate         *string   `gorm:"type:varchar(10)" json:"end_date,omitempty"`
	FileURL         string    `gorm:"type:text;not null" json:"file_url"`
	MimeType        string    `gorm:"type:varchar(50);not null" json:"mime_type"`
	CreatedAt       time.Time `gorm:"not null;default:now()" json:"created_at"`
}
