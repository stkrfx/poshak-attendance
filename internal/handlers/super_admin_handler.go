package handlers

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stkrfx/poshak-attendance/internal/config"
	"github.com/stkrfx/poshak-attendance/internal/middleware"
	"github.com/stkrfx/poshak-attendance/internal/models"
	"github.com/stkrfx/poshak-attendance/internal/services"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var nonAlphanumeric = regexp.MustCompile(`[^a-z0-9]+`)

type SuperAdminHandler struct {
	db        *gorm.DB
	cfg       *config.Config
	sheetsSvc *services.SheetsSyncService
}

func NewSuperAdminHandler(db *gorm.DB, cfg *config.Config, sheetsSvc *services.SheetsSyncService) *SuperAdminHandler {
	return &SuperAdminHandler{db: db, cfg: cfg, sheetsSvc: sheetsSvc}
}

type BootstrapSuperUserRequest struct {
	SetupSecret    string `json:"setup_secret" validate:"required"`
	FullName       string `json:"full_name" validate:"required"`
	Email          string `json:"email" validate:"required,email"`
	MobileNumber   string `json:"mobile_number" validate:"required,len=10"`
	Password       string `json:"password" validate:"required,min=8"`
	PrivilegeLevel string `json:"privilege_level" validate:"required,oneof=ADMIN DEVELOPER"`
}

func (h *SuperAdminHandler) BootstrapSuperUser(w http.ResponseWriter, r *http.Request) {
	var req BootstrapSuperUserRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Invalid bootstrap request payload.",
		})
		return
	}

	if h.cfg.SuperSetupSecret == "" || req.SetupSecret != h.cfg.SuperSetupSecret {
		middleware.WriteJSON(w, http.StatusForbidden, middleware.APIResponse{
			Success: false,
			Message: "Invalid SUPER_SETUP_SECRET.",
		})
		return
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	su := models.SuperUser{
		FullName:       strings.TrimSpace(req.FullName),
		Email:          strings.ToLower(strings.TrimSpace(req.Email)),
		MobileNumber:   strings.TrimSpace(req.MobileNumber),
		PasswordHash:   string(hashed),
		PrivilegeLevel: req.PrivilegeLevel,
	}

	if err := h.db.Create(&su).Error; err != nil {
		middleware.WriteJSON(w, http.StatusConflict, middleware.APIResponse{
			Success: false,
			Message: "SuperUser with this email or mobile number already exists.",
		})
		return
	}

	middleware.WriteJSON(w, http.StatusCreated, middleware.APIResponse{
		Success: true,
		Message: "SuperUser account created in super_users table.",
		Data:    su,
	})
}

type SuperLoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func (h *SuperAdminHandler) SuperLogin(w http.ResponseWriter, r *http.Request) {
	var req SuperLoginRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Email and password required.",
		})
		return
	}

	var su models.SuperUser
	if err := h.db.First(&su, "LOWER(email) = ?", strings.ToLower(strings.TrimSpace(req.Email))).Error; err != nil {
		middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
			Success: false,
			Message: "Invalid super user credentials.",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(su.PasswordHash), []byte(req.Password)); err != nil {
		middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
			Success: false,
			Message: "Invalid super user credentials.",
		})
		return
	}

	claims := jwt.MapClaims{
		"sub":  su.ID.String(),
		"priv": su.PrivilegeLevel,
		"exp":  time.Now().UTC().Add(12 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(h.cfg.SuperJWTSecret))

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"super_token": signed,
			"super_user":  su,
		},
	})
}

type CreateEmployeeRequest struct {
	Name         string `json:"name" validate:"required"`
	MobileNumber string `json:"mobile_number" validate:"required,len=10"`
	Gender       string `json:"gender" validate:"required"`
	Password     string `json:"password" validate:"required,min=6"`
}

func (h *SuperAdminHandler) CreateEmployee(w http.ResponseWriter, r *http.Request) {
	var req CreateEmployeeRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Name, 10-digit Mobile Number, Gender, and Password (min 6 chars) are required.",
		})
		return
	}

	baseSlug := nonAlphanumeric.ReplaceAllString(strings.ToLower(req.Name), "")
	if baseSlug == "" {
		baseSlug = "emp"
	}
	suffix := req.MobileNumber[len(req.MobileNumber)-4:]
	autoUsername := fmt.Sprintf("%s_%s", baseSlug, suffix)

	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	emp := models.User{
		Name:                strings.TrimSpace(req.Name),
		Username:            autoUsername,
		MobileNumber:        strings.TrimSpace(req.MobileNumber),
		Gender:              strings.TrimSpace(req.Gender),
		PasswordHash:        string(hashed),
		IsDOBLocked:         false,
		CanEditUsername:     true,
		CanUploadDocuments:  true,
		IsBlocked:           false,
	}

	if err := h.db.Create(&emp).Error; err != nil {
		middleware.WriteJSON(w, http.StatusConflict, middleware.APIResponse{
			Success: false,
			Message: "Employee with this Google Sheet Name or Mobile Number already exists.",
		})
		return
	}

	middleware.WriteJSON(w, http.StatusCreated, middleware.APIResponse{
		Success: true,
		Message: "Employee created successfully.",
		Data:    emp,
	})
}

func (h *SuperAdminHandler) ListEmployees(w http.ResponseWriter, r *http.Request) {
	var users []models.User
	_ = h.db.Order("name ASC").Find(&users).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Data:    users,
	})
}

type BlockUserRequest struct {
	Reason *string `json:"reason,omitempty"`
}

func (h *SuperAdminHandler) BlockEmployee(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Invalid employee ID.",
		})
		return
	}

	var req BlockUserRequest
	_ = middleware.DecodeAndValidate(r, &req)

	var user models.User
	if err := h.db.First(&user, "id = ?", targetID).Error; err != nil {
		middleware.WriteJSON(w, http.StatusNotFound, middleware.APIResponse{
			Success: false,
			Message: "Employee not found.",
		})
		return
	}

	user.IsBlocked = true
	user.BlockedReason = req.Reason
	user.UpdatedAt = time.Now().UTC()
	_ = h.db.Save(&user).Error

	// Immediately revoke all active device sessions for this blocked user
	_ = h.db.Delete(&models.DeviceSession{}, "user_id = ?", user.ID).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Employee account blocked and all active device sessions revoked.",
		Data:    user,
	})
}

func (h *SuperAdminHandler) UnblockEmployee(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Invalid employee ID.",
		})
		return
	}

	var user models.User
	if err := h.db.First(&user, "id = ?", targetID).Error; err != nil {
		middleware.WriteJSON(w, http.StatusNotFound, middleware.APIResponse{
			Success: false,
			Message: "Employee not found.",
		})
		return
	}

	user.IsBlocked = false
	user.BlockedReason = nil
	user.UpdatedAt = time.Now().UTC()
	_ = h.db.Save(&user).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Employee account unblocked.",
		Data:    user,
	})
}

type DeveloperModerationRequest struct {
	ForceUsername      *string `json:"force_username,omitempty"`
	CanEditUsername    *bool   `json:"can_edit_username,omitempty"`
	PurgeAllDocuments  bool    `json:"purge_all_documents"`
	CanUploadDocuments *bool   `json:"can_upload_documents,omitempty"`
	OverrideDOB        *string `json:"override_dob,omitempty"`
}

func (h *SuperAdminHandler) ModerateEmployee(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Invalid employee ID.",
		})
		return
	}

	var req DeveloperModerationRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Invalid moderation payload.",
		})
		return
	}

	var user models.User
	if err := h.db.First(&user, "id = ?", targetID).Error; err != nil {
		middleware.WriteJSON(w, http.StatusNotFound, middleware.APIResponse{
			Success: false,
			Message: "Employee not found.",
		})
		return
	}

	if req.ForceUsername != nil && strings.TrimSpace(*req.ForceUsername) != "" {
		user.Username = strings.ToLower(strings.TrimSpace(*req.ForceUsername))
	}
	if req.CanEditUsername != nil {
		user.CanEditUsername = *req.CanEditUsername
	}
	if req.PurgeAllDocuments {
		_ = h.db.Delete(&models.UserDocument{}, "user_id = ?", user.ID).Error
	}
	if req.CanUploadDocuments != nil {
		user.CanUploadDocuments = *req.CanUploadDocuments
	}
	if req.OverrideDOB != nil && strings.TrimSpace(*req.OverrideDOB) != "" {
		dob := strings.TrimSpace(*req.OverrideDOB)
		user.DOB = &dob
		user.IsDOBLocked = true
	}

	user.UpdatedAt = time.Now().UTC()
	_ = h.db.Save(&user).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Moderation settings updated.",
		Data:    user,
	})
}

func (h *SuperAdminHandler) TriggerSheetsSync(w http.ResponseWriter, r *http.Request) {
	if err := h.sheetsSvc.SyncAllActiveMonths(r.Context()); err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: fmt.Sprintf("Google Sheets sync failed: %v", err),
		})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Google Sheets attendance and summary data synced successfully.",
	})
}

type CreateNotificationRequest struct {
	UserID *uuid.UUID `json:"user_id,omitempty"`
	Title  string     `json:"title" validate:"required"`
	Body   string     `json:"body" validate:"required"`
}

func (h *SuperAdminHandler) SendNotification(w http.ResponseWriter, r *http.Request) {
	var req CreateNotificationRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Notification title and body are required.",
		})
		return
	}

	notif := models.Notification{
		UserID: req.UserID,
		Title:  strings.TrimSpace(req.Title),
		Body:   strings.TrimSpace(req.Body),
	}
	_ = h.db.Create(&notif).Error

	middleware.WriteJSON(w, http.StatusCreated, middleware.APIResponse{
		Success: true,
		Message: "Notification published.",
		Data:    notif,
	})
}

type PublishReleaseRequest struct {
	VersionName    string `json:"version_name" validate:"required"`
	VersionCode    int    `json:"version_code" validate:"required,min=1"`
	APKDownloadURL string `json:"apk_download_url" validate:"required"`
	ReleaseNotes   string `json:"release_notes" validate:"required"`
	IsForceUpdate  bool   `json:"is_force_update"`
}

func (h *SuperAdminHandler) PublishAppRelease(w http.ResponseWriter, r *http.Request) {
	var req PublishReleaseRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Valid version_name, version_code, apk_download_url, and release_notes are required.",
		})
		return
	}

	rel := models.AppRelease{
		VersionName:    strings.TrimSpace(req.VersionName),
		VersionCode:    req.VersionCode,
		APKDownloadURL: strings.TrimSpace(req.APKDownloadURL),
		ReleaseNotes:   strings.TrimSpace(req.ReleaseNotes),
		IsForceUpdate:  req.IsForceUpdate,
	}

	if err := h.db.Create(&rel).Error; err != nil {
		middleware.WriteJSON(w, http.StatusConflict, middleware.APIResponse{
			Success: false,
			Message: "This version_code already exists.",
		})
		return
	}

	middleware.WriteJSON(w, http.StatusCreated, middleware.APIResponse{
		Success: true,
		Message: "APK release published.",
		Data:    rel,
	})
}
