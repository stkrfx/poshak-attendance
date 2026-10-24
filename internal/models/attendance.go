package models

import (
	"time"

	"github.com/google/uuid"
)

// MonthlyAttendanceSummary stores exact pre-calculated values from Columns B, C, D, E, F of Google Sheets.
type MonthlyAttendanceSummary struct {
	ID             uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID         uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_user_month;constraint:OnDelete:CASCADE" json:"user_id"`
	MonthSheetName string    `gorm:"type:varchar(20);not null;uniqueIndex:idx_user_month" json:"month_sheet_name"`
	SundayModeS    string    `gorm:"type:varchar(10);not null" json:"sunday_mode_s"`
	TotalPresentP  string    `gorm:"type:varchar(20);not null" json:"total_present_p"`
	TotalAbsentA   string    `gorm:"type:varchar(20);not null" json:"total_absent_a"`
	TotalPayableG  string    `gorm:"type:varchar(20);not null" json:"total_payable_g"`
	TotalPaidT     string    `gorm:"type:varchar(20);not null" json:"total_paid_t"`
	SyncedAt       time.Time `gorm:"not null;default:now()" json:"synced_at"`
}

// AttendanceRecord stores daily attendance cells from Columns G to AK (Days 1 to 31) and cell notes.
type AttendanceRecord struct {
	ID             uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID         uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_user_date;constraint:OnDelete:CASCADE" json:"user_id"`
	AttendanceDate string    `gorm:"type:varchar(10);not null;uniqueIndex:idx_user_date" json:"attendance_date"` // YYYY-MM-DD
	MonthSheetName string    `gorm:"type:varchar(20);not null;index" json:"month_sheet_name"`
	Status         string    `gorm:"type:varchar(20);not null" json:"status"` // "P", "A", "H", "UNMARKED", "NA"
	Note           *string   `gorm:"type:text" json:"note,omitempty"`
}
