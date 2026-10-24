package handlers

import (
	"net/http"

	"github.com/stkrfx/poshak-attendance/internal/middleware"
	"github.com/stkrfx/poshak-attendance/internal/models"
	"github.com/stkrfx/poshak-attendance/internal/services"
	"gorm.io/gorm"
)

type UserAttendanceHandler struct {
	db        *gorm.DB
	sheetsSvc *services.SheetsSyncService
}

func NewUserAttendanceHandler(db *gorm.DB, sheetsSvc *services.SheetsSyncService) *UserAttendanceHandler {
	return &UserAttendanceHandler{db: db, sheetsSvc: sheetsSvc}
}

type MonthAttendanceBundle struct {
	MonthSheetName string                           `json:"month_sheet_name"`
	Summary        *models.MonthlyAttendanceSummary `json:"summary,omitempty"`
	Days           []models.AttendanceRecord        `json:"days"`
}

// GetAttendance returns Current Month + Previous 2 Months attendance summaries (S, P, A, G, T) and daily cells.
func (h *UserAttendanceHandler) GetAttendance(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)
	activeMonths := h.sheetsSvc.ActiveMonthNames()

	bundles := make([]MonthAttendanceBundle, 0, len(activeMonths))
	for _, mName := range activeMonths {
		var summary models.MonthlyAttendanceSummary
		var summaryPtr *models.MonthlyAttendanceSummary
		if err := h.db.First(&summary, "user_id = ? AND month_sheet_name = ?", user.ID, mName).Error; err == nil {
			summaryPtr = &summary
		}

		var days []models.AttendanceRecord
		_ = h.db.Order("attendance_date ASC").Find(&days, "user_id = ? AND month_sheet_name = ?", user.ID, mName).Error

		bundles = append(bundles, MonthAttendanceBundle{
			MonthSheetName: mName,
			Summary:        summaryPtr,
			Days:           days,
		})
	}

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"allowed_months": activeMonths,
			"months":         bundles,
		},
	})
}
