package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
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

type UserAuthHandler struct {
	db          *gorm.DB
	cfg         *config.Config
	firebaseSvc *services.FirebaseAuthService
	emailSvc    *services.EmailService
}

func NewUserAuthHandler(db *gorm.DB, cfg *config.Config, firebaseSvc *services.FirebaseAuthService, emailSvc *services.EmailService) *UserAuthHandler {
	return &UserAuthHandler{
		db:          db,
		cfg:         cfg,
		firebaseSvc: firebaseSvc,
		emailSvc:    emailSvc,
	}
}

type LoginRequest struct {
	Identifier       string  `json:"identifier" validate:"required,min=3"`
	Password         string  `json:"password" validate:"required,min=6"`
	DeviceHardwareID string  `json:"device_hardware_id" validate:"required"`
	DeviceBrand      string  `json:"device_brand" validate:"required"`
	DeviceModel      string  `json:"device_model" validate:"required"`
	OSVersion        string  `json:"os_version" validate:"required"`
	FCMToken         *string `json:"fcm_token,omitempty"`
}

func (h *UserAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Please enter a valid mobile number, username, or email and password.",
		})
		return
	}

	identifier := strings.TrimSpace(req.Identifier)
	var user models.User
	err := h.db.Where(
		"mobile_number = ? OR LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
		identifier, identifier, identifier,
	).First(&user).Error

	if err != nil {
		middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
			Success: false,
			Message: "Invalid login details. Please check and try again.",
		})
		return
	}

	if user.IsBlocked {
		middleware.WriteJSON(w, http.StatusForbidden, middleware.APIResponse{
			Success: false,
			Code:    "ACCOUNT_BLOCKED",
			Message: "Your account has been restricted by the shop owner.",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
			Success: false,
			Message: "Incorrect password. Please try again.",
		})
		return
	}

	rawRefreshToken, refreshHash := generateRefreshTokenPair()
	sessionID := uuid.New()

	session := models.DeviceSession{
		ID:               sessionID,
		UserID:           user.ID,
		DeviceHardwareID: req.DeviceHardwareID,
		DeviceBrand:      req.DeviceBrand,
		DeviceModel:      req.DeviceModel,
		OSVersion:        req.OSVersion,
		RefreshTokenHash: refreshHash,
		FCMToken:         req.FCMToken,
		LastActiveAt:     time.Now().UTC(),
	}

	accessToken, err := h.issueAccessToken(user.ID, session.ID)
	if err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Could not generate session token.",
		})
		return
	}

	if err := h.db.Create(&session).Error; err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Could not start your session. Please try again.",
		})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"access_token":  accessToken,
			"refresh_token": rawRefreshToken,
			"session_id":    session.ID,
			"user":          user,
		},
	})
}

type RefreshTokenRequest struct {
	SessionID    string `json:"session_id" validate:"required,uuid"`
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func (h *UserAuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Invalid session refresh request.",
		})
		return
	}

	sessionUUID, _ := uuid.Parse(req.SessionID)
	var session models.DeviceSession
	if err := h.db.First(&session, "id = ?", sessionUUID).Error; err != nil {
		middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
			Success: false,
			Code:    "SESSION_EXPIRED",
			Message: "Your session has ended. Please log in again.",
		})
		return
	}

	var user models.User
	if err := h.db.First(&user, "id = ?", session.UserID).Error; err != nil || user.IsBlocked {
		_ = h.db.Delete(&models.DeviceSession{}, "user_id = ?", session.UserID).Error
		middleware.WriteJSON(w, http.StatusForbidden, middleware.APIResponse{
			Success: false,
			Code:    "ACCOUNT_BLOCKED",
			Message: "Your account is not accessible.",
		})
		return
	}

	incomingHash := hashToken(req.RefreshToken)
	if session.RefreshTokenHash != incomingHash {
		// Possible token reuse: revoke this device session immediately
		_ = h.db.Delete(&session).Error
		middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
			Success: false,
			Code:    "INVALID_REFRESH_TOKEN",
			Message: "Session expired. Please log in again.",
		})
		return
	}

	// Rotate refresh token

	// Rotate refresh token
	newRawRefresh, newRefreshHash := generateRefreshTokenPair()
	session.RefreshTokenHash = newRefreshHash
	session.LastActiveAt = time.Now().UTC()

	if err := h.db.Save(&session).Error; err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Code:    "TOKEN_REFRESH_FAILED",
			Message: "Could not refresh your session. Please try again.",
		})
		return
	}

	newAccessToken, err := h.issueAccessToken(user.ID, session.ID)
	if err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Could not refresh token.",
		})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"access_token":  newAccessToken,
			"refresh_token": newRawRefresh,
			"session_id":    session.ID,
			"user":          user,
		},
	})
}

type ForgotPasswordEmailOTPRequest struct {
	Email string `json:"email" validate:"required,email"`
}

func (h *UserAuthHandler) SendForgotPasswordEmailOTP(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordEmailOTPRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Please enter a valid email address.",
		})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	var user models.User
	if err := h.db.First(&user, "LOWER(email) = ?", email).Error; err != nil {
		middleware.WriteJSON(w, http.StatusNotFound, middleware.APIResponse{
			Success: false,
			Message: "No employee account found with this email address.",
		})
		return
	}

	otpCode := generateSixDigitOTP()

	if err := h.db.Delete(
		&models.EmailOTP{},
		"LOWER(email) = ? AND purpose = ?",
		email,
		"RESET_PASSWORD",
	).Error; err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Could not prepare a password-reset code. Please try again.",
		})
		return
	}

	otpEntry := models.EmailOTP{
		Email:     email,
		OTPCode:   otpCode,
		Purpose:   "RESET_PASSWORD",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}

	if err := h.db.Create(&otpEntry).Error; err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Could not create a password-reset code. Please try again.",
		})
		return
	}

	if err := h.emailSvc.SendOTP(email, otpCode, "RESET_PASSWORD"); err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Could not send verification email. Please try mobile verification.",
		})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "A 6-digit verification code has been sent to your email.",
	})
}

type ResetPasswordRequest struct {
	Method          string `json:"method" validate:"required,oneof=FIREBASE_SMS EMAIL_OTP"`
	FirebaseIDToken string `json:"firebase_id_token,omitempty"`
	Email           string `json:"email,omitempty"`
	OTPCode         string `json:"otp_code,omitempty"`
	NewPassword     string `json:"new_password" validate:"required,min=6"`
}

func (h *UserAuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Please provide valid password reset details (minimum 6 characters).",
		})
		return
	}

	var user models.User
	var otpRecord models.EmailOTP

	switch req.Method {
	case "FIREBASE_SMS":
		if strings.TrimSpace(req.FirebaseIDToken) == "" {
			middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
				Success: false,
				Message: "Mobile verification token is required.",
			})
			return
		}
		mobileNumber, err := h.firebaseSvc.VerifyPhoneIDToken(r.Context(), req.FirebaseIDToken)
		if err != nil {
			middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
				Success: false,
				Message: "Mobile OTP verification failed or expired.",
			})
			return
		}
		if err := h.db.First(&user, "mobile_number = ?", mobileNumber).Error; err != nil {
			middleware.WriteJSON(w, http.StatusNotFound, middleware.APIResponse{
				Success: false,
				Message: "No employee account matches this mobile number.",
			})
			return
		}

	case "EMAIL_OTP":
		email := strings.ToLower(strings.TrimSpace(req.Email))
		err := h.db.First(&otpRecord, "LOWER(email) = ? AND otp_code = ? AND purpose = ?", email, strings.TrimSpace(req.OTPCode), "RESET_PASSWORD").Error
		if err != nil || time.Now().UTC().After(otpRecord.ExpiresAt) {
			middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
				Success: false,
				Message: "Invalid or expired 6-digit email code.",
			})
			return
		}
		if err := h.db.First(&user, "LOWER(email) = ?", email).Error; err != nil {
			middleware.WriteJSON(w, http.StatusNotFound, middleware.APIResponse{
				Success: false,
				Message: "Account not found.",
			})
			return
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Failed to save new password.",
		})
		return
	}

	user.PasswordHash = string(hashed)
	user.UpdatedAt = time.Now().UTC()

	err = h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&user).Error; err != nil {
			return err
		}

		if req.Method == "EMAIL_OTP" {
			result := tx.Delete(
				&models.EmailOTP{},
				"id = ? AND purpose = ? AND expires_at > ?",
				otpRecord.ID,
				"RESET_PASSWORD",
				time.Now().UTC(),
			)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return gorm.ErrRecordNotFound
			}
		}

		if err := tx.Where("user_id = ?", user.ID).
			Delete(&models.DeviceSession{}).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		middleware.WriteJSON(w, http.StatusUnauthorized, middleware.APIResponse{
			Success: false,
			Message: "Password reset could not be completed. Please request a new verification code and try again.",
		})
		return
	}

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Your password has been updated. You can now log in.",
	})

}

func (h *UserAuthHandler) issueAccessToken(userID, sessionID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"sid": sessionID.String(),
		"exp": time.Now().UTC().Add(6 * time.Hour).Unix(),
		"iat": time.Now().UTC().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.cfg.UserJWTSecret))
}

func generateRefreshTokenPair() (string, string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	raw := hex.EncodeToString(b)
	return raw, hashToken(raw)
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func generateSixDigitOTP() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "123456"
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}
