package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stkrfx/poshak-attendance/internal/models"
	"gorm.io/gorm"
)

type contextKey string

const (
	UserContextKey    contextKey = "authenticated_user"
	SessionContextKey contextKey = "authenticated_session_id"
)

func UserAuthMiddleware(db *gorm.DB, jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Code:    "UNAUTHORIZED",
					Message: "Please log in to continue.",
				})
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
				return []byte(jwtSecret), nil
			})
			if err != nil || !token.Valid {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Code:    "INVALID_TOKEN",
					Message: "Your session has expired. Please log in again.",
				})
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Code:    "INVALID_CLAIMS",
					Message: "Invalid session token.",
				})
				return
			}

			userIDStr, _ := claims["sub"].(string)
			sessionIDStr, _ := claims["sid"].(string)
			userID, err1 := uuid.Parse(userIDStr)
			sessionID, err2 := uuid.Parse(sessionIDStr)
			if err1 != nil || err2 != nil {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Code:    "INVALID_SESSION",
					Message: "Invalid session identifier.",
				})
				return
			}

			var user models.User
			if err := db.First(&user, "id = ?", userID).Error; err != nil {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Code:    "USER_NOT_FOUND",
					Message: "Account no longer exists.",
				})
				return
			}

			// Validate the device session before returning any account/profile details.
			// A revoked session must not be able to probe whether an account is blocked.
			var session models.DeviceSession
			if err := db.First(&session, "id = ? AND user_id = ?", sessionID, user.ID).Error; err != nil {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Code:    "SESSION_REVOKED",
					Message: "This device has been logged out.",
				})
				return
			}

			// Blocked sessions get an explicit status and safe profile payload so the app
			// can show the required blocked-account screen after local unlock.
			if user.IsBlocked {
				blockedReason := "Your account has been restricted by the shop owner."
				if user.BlockedReason != nil && strings.TrimSpace(*user.BlockedReason) != "" {
					blockedReason = strings.TrimSpace(*user.BlockedReason)
				}
				middlewareData := map[string]interface{}{
					"blocked_reason": blockedReason,
					"user":           user,
				}
				WriteJSON(w, http.StatusForbidden, APIResponse{
					Success: false,
					Code:    "ACCOUNT_BLOCKED",
					Message: "Your account has been restricted by the shop owner.",
					Data:    middlewareData,
				})
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			ctx = context.WithValue(ctx, SessionContextKey, sessionID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetAuthenticatedUser(r *http.Request) models.User {
	u, _ := r.Context().Value(UserContextKey).(models.User)
	return u
}

func GetAuthenticatedSessionID(r *http.Request) uuid.UUID {
	sid, _ := r.Context().Value(SessionContextKey).(uuid.UUID)
	return sid
}
