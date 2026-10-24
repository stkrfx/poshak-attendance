package handlers

import (
	"net/http"
	"strconv"

	"github.com/stkrfx/poshak-attendance/internal/middleware"
	"github.com/stkrfx/poshak-attendance/internal/models"
	"gorm.io/gorm"
)

type UserSystemHandler struct {
	db *gorm.DB
}

func NewUserSystemHandler(db *gorm.DB) *UserSystemHandler {
	return &UserSystemHandler{db: db}
}

func (h *UserSystemHandler) CheckAppVersion(w http.ResponseWriter, r *http.Request) {
	currentCode, _ := strconv.Atoi(r.URL.Query().Get("version_code"))

	var latest models.AppRelease
	if err := h.db.Order("version_code DESC").First(&latest).Error; err != nil {
		middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"update_required": false,
			},
		})
		return
	}

	updateRequired := currentCode > 0 && currentCode < latest.VersionCode && latest.IsForceUpdate
	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"update_required": updateRequired,
			"latest_release":  latest,
		},
	})
}

func (h *UserSystemHandler) ListNotifications(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)

	var items []models.Notification
	_ = h.db.Order("created_at DESC").Limit(50).
		Find(&items, "user_id = ? OR user_id IS NULL", user.ID).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Data:    items,
	})
}

func (h *UserSystemHandler) MarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)

	_ = h.db.Model(&models.Notification{}).
		Where("user_id = ?", user.ID).
		Update("is_read", true).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "All notifications marked as read.",
	})
}
