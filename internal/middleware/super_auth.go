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

const SuperUserContextKey contextKey = "authenticated_super_user"

func SuperAuthMiddleware(db *gorm.DB, superSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Code:    "SUPER_UNAUTHORIZED",
					Message: "Admin/Developer authorization token required.",
				})
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
				return []byte(superSecret), nil
			})
			if err != nil || !token.Valid {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Code:    "INVALID_SUPER_TOKEN",
					Message: "Invalid or expired Admin/Developer token.",
				})
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Message: "Invalid token claims.",
				})
				return
			}

			superIDStr, _ := claims["sub"].(string)
			superID, err := uuid.Parse(superIDStr)
			if err != nil {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Message: "Invalid super user ID.",
				})
				return
			}

			var superUser models.SuperUser
			if err := db.First(&superUser, "id = ?", superID).Error; err != nil {
				WriteJSON(w, http.StatusUnauthorized, APIResponse{
					Success: false,
					Message: "Super user account not found.",
				})
				return
			}

			ctx := context.WithValue(r.Context(), SuperUserContextKey, superUser)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetAuthenticatedSuperUser(r *http.Request) models.SuperUser {
	su, _ := r.Context().Value(SuperUserContextKey).(models.SuperUser)
	return su
}
