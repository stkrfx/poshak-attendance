package handlers

import (
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stkrfx/poshak-attendance/internal/middleware"
	"github.com/stkrfx/poshak-attendance/internal/models"
	"github.com/stkrfx/poshak-attendance/internal/services"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9_]{3,30}$`)
var datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

type UserProfileHandler struct {
	db       *gorm.DB
	emailSvc *services.EmailService
}

func NewUserProfileHandler(db *gorm.DB, emailSvc *services.EmailService) *UserProfileHandler {
	return &UserProfileHandler{db: db, emailSvc: emailSvc}
}

func (h *UserProfileHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)
	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Data:    user,
	})
}

type UpdateProfileRequest struct {
	Username  *string `json:"username,omitempty"`
	DOB       *string `json:"dob,omitempty"`
	Address   *string `json:"address,omitempty"`
	AvatarURL *string `json:"avatar_url,omitempty"`
}

func (h *UserProfileHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)

	if !user.CanEditProfile {
		middleware.WriteJSON(w, http.StatusForbidden, middleware.APIResponse{
			Success: false,
			Code:    "PROFILE_EDIT_RESTRICTED",
			Message: "Profile editing has been disabled for your account.",
		})
		return
	}

	var req UpdateProfileRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Invalid profile details submitted.",
		})
		return
	}

	if req.Username != nil {
		newUsername := strings.ToLower(strings.TrimSpace(*req.Username))
		if newUsername != user.Username {

			if !usernamePattern.MatchString(newUsername) {
				middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
					Success: false,
					Message: "Username must be 3-30 characters using only lowercase letters, numbers, or underscores.",
				})
				return
			}
			var count int64
			h.db.Model(&models.User{}).Where("LOWER(username) = ? AND id != ?", newUsername, user.ID).Count(&count)
			if count > 0 {
				middleware.WriteJSON(w, http.StatusConflict, middleware.APIResponse{
					Success: false,
					Message: "This username is already taken. Please try another.",
				})
				return
			}
			user.Username = newUsername
		}
	}

	if req.DOB != nil && strings.TrimSpace(*req.DOB) != "" {
		dobStr := strings.TrimSpace(*req.DOB)
		if user.IsDOBLocked {
			middleware.WriteJSON(w, http.StatusForbidden, middleware.APIResponse{
				Success: false,
				Message: "Date of Birth can only be set once.",
			})
			return
		}
		if !datePattern.MatchString(dobStr) {
			middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
				Success: false,
				Message: "Please select a valid date (YYYY-MM-DD).",
			})
			return
		}
		user.DOB = &dobStr
		user.IsDOBLocked = true
	}

	if req.Address != nil {
		trimmed := strings.TrimSpace(*req.Address)
		if trimmed == "" {
			user.Address = nil
		} else {
			user.Address = &trimmed
		}
	}

	if req.AvatarURL != nil {
		trimmed := strings.TrimSpace(*req.AvatarURL)
		if trimmed == "" {
			user.AvatarURL = nil
		} else {
			user.AvatarURL = &trimmed
		}
	}

	user.UpdatedAt = time.Now().UTC()
	if err := h.db.Save(&user).Error; err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Could not save profile changes.",
		})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Profile updated successfully.",
		Data:    user,
	})
}

type SendEmailOTPRequest struct {
	Email string `json:"email" validate:"required,email"`
}

func (h *UserProfileHandler) SendEmailVerificationOTP(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)
	log.Printf("[EMAIL-OTP-HANDLER] Incoming request to send email verification OTP from user_id=%s (username=%s, name=%s)",
		user.ID, user.Username, user.Name)

	var req SendEmailOTPRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		log.Printf("[EMAIL-OTP-HANDLER] Validation failed for user_id=%s: %v", user.ID, err)
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Please enter a valid email address.",
		})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	log.Printf("[EMAIL-OTP-HANDLER] Checking if email=%s is already in use by another employee...", email)

	var count int64
	h.db.Model(&models.User{}).Where("LOWER(email) = ? AND id != ?", email, user.ID).Count(&count)
	if count > 0 {
		log.Printf("[EMAIL-OTP-HANDLER] Conflict: email=%s is already linked to another user account", email)
		middleware.WriteJSON(w, http.StatusConflict, middleware.APIResponse{
			Success: false,
			Message: "This email address is already linked to another account.",
		})
		return
	}

	otpCode := generateSixDigitOTP()
	if err := h.db.Delete(&models.EmailOTP{}, "LOWER(email) = ? AND purpose = ?", email, "VERIFY_EMAIL").Error; err != nil {
		log.Printf("[EMAIL-OTP-DB] Warning while clearing old OTPs for email=%s: %v", email, err)
	}

	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	otpEntry := models.EmailOTP{
		Email:     email,
		OTPCode:   otpCode,
		Purpose:   "VERIFY_EMAIL",
		ExpiresAt: expiresAt,
	}

	if err := h.db.Create(&otpEntry).Error; err != nil {
		log.Printf("[EMAIL-OTP-DB] ERROR: Could not save OTP record to PostgreSQL for email=%s: %v", email, err)
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Could not generate verification code. Please try again.",
		})
		return
	}
	log.Printf("[EMAIL-OTP-DB] Saved OTP record id=%s for email=%s (expires_at=%s)",
		otpEntry.ID, email, expiresAt.Format(time.RFC3339))

	if err := h.emailSvc.SendOTP(email, otpCode, "VERIFY_EMAIL"); err != nil {
		log.Printf("[EMAIL-OTP-HANDLER] ERROR: SMTP SendOTP failed for user_id=%s, email=%s: %v", user.ID, email, err)
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Failed to send verification code to this email.",
		})
		return
	}

	log.Printf("[EMAIL-OTP-HANDLER] SUCCESS: OTP sent to email=%s for user_id=%s", email, user.ID)
	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "A 6-digit verification code has been sent to your email.",
	})
}

type VerifyEmailOTPRequest struct {
	Email   string `json:"email" validate:"required,email"`
	OTPCode string `json:"otp_code" validate:"required,len=6"`
}

func (h *UserProfileHandler) VerifyEmailOTP(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)
	log.Printf("[EMAIL-OTP-VERIFY] Incoming OTP verification request from user_id=%s (username=%s)",
		user.ID, user.Username)

	var req VerifyEmailOTPRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		log.Printf("[EMAIL-OTP-VERIFY] Validation failed for user_id=%s: %v", user.ID, err)
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Please enter the 6-digit code sent to your email.",
		})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	code := strings.TrimSpace(req.OTPCode)
	log.Printf("[EMAIL-OTP-VERIFY] Looking up OTP record for email=%s, submitted_code=%s", email, code)

	var otpRecord models.EmailOTP
	err := h.db.First(&otpRecord, "LOWER(email) = ? AND otp_code = ? AND purpose = ?", email, code, "VERIFY_EMAIL").Error
	if err != nil {
		log.Printf("[EMAIL-OTP-VERIFY] FAILED: No matching OTP found in DB for email=%s (err=%v)", email, err)
		middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
			Success: false,
			Message: "Invalid or expired 6-digit verification code.",
		})
		return
	}

	if time.Now().UTC().After(otpRecord.ExpiresAt) {
		log.Printf("[EMAIL-OTP-VERIFY] FAILED: OTP for email=%s expired at %s",
			email, otpRecord.ExpiresAt.Format(time.RFC3339))
		middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
			Success: false,
			Message: "Invalid or expired 6-digit verification code.",
		})
		return
	}

	user.Email = &email
	user.UpdatedAt = time.Now().UTC()
	if err := h.db.Save(&user).Error; err != nil {
		log.Printf("[EMAIL-OTP-VERIFY] ERROR: Failed to update email column for user_id=%s: %v", user.ID, err)
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Could not link email address.",
		})
		return
	}

	_ = h.db.Delete(&otpRecord).Error
	log.Printf("[EMAIL-OTP-VERIFY] SUCCESS: Email=%s verified and saved for user_id=%s", email, user.ID)

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Email address verified and saved.",
		Data:    user,
	})
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=6"`
}

func (h *UserProfileHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)

	var req ChangePasswordRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "New password must be at least 6 characters long.",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
			Success: false,
			Message: "Your current password is incorrect.",
		})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Failed to update password.",
		})
		return
	}

	user.PasswordHash = string(hashed)
	user.UpdatedAt = time.Now().UTC()
	_ = h.db.Save(&user).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Password changed successfully.",
	})
}

func (h *UserProfileHandler) GetLoggedInDevices(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)
	currentSessionID := middleware.GetAuthenticatedSessionID(r)

	var sessions []models.DeviceSession
	_ = h.db.Order("last_active_at DESC").Find(&sessions, "user_id = ?", user.ID).Error

	type DeviceItem struct {
		ID               uuid.UUID `json:"id"`
		DeviceBrand      string    `json:"device_brand"`
		DeviceModel      string    `json:"device_model"`
		OSVersion        string    `json:"os_version"`
		LastActiveAt     time.Time `json:"last_active_at"`
		CreatedAt        time.Time `json:"created_at"`
		IsCurrentSession bool      `json:"is_current_session"`
	}

	result := make([]DeviceItem, 0, len(sessions))
	for _, s := range sessions {
		result = append(result, DeviceItem{
			ID:               s.ID,
			DeviceBrand:      s.DeviceBrand,
			DeviceModel:      s.DeviceModel,
			OSVersion:        s.OSVersion,
			LastActiveAt:     s.LastActiveAt,
			CreatedAt:        s.CreatedAt,
			IsCurrentSession: s.ID == currentSessionID,
		})
	}

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Data:    result,
	})
}

func (h *UserProfileHandler) LogoutCurrentDevice(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)
	currentSessionID := middleware.GetAuthenticatedSessionID(r)

	_ = h.db.Delete(&models.DeviceSession{}, "id = ? AND user_id = ?", currentSessionID, user.ID).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Logged out from this phone.",
	})
}

func (h *UserProfileHandler) LogoutAllOtherDevices(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)
	currentSessionID := middleware.GetAuthenticatedSessionID(r)

	_ = h.db.Delete(&models.DeviceSession{}, "user_id = ? AND id != ?", user.ID, currentSessionID).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Logged out from all other phones.",
	})
}

func (h *UserProfileHandler) LogoutSpecificDevice(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)
	targetSessionStr := r.PathValue("session_id")
	targetID, err := uuid.Parse(targetSessionStr)
	if err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Invalid device session ID.",
		})
		return
	}

	_ = h.db.Delete(&models.DeviceSession{}, "id = ? AND user_id = ?", targetID, user.ID).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Selected phone has been logged out.",
	})
}
