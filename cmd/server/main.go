package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stkrfx/poshak-attendance/internal/config"
	"github.com/stkrfx/poshak-attendance/internal/database"
	"github.com/stkrfx/poshak-attendance/internal/handlers"
	"github.com/stkrfx/poshak-attendance/internal/middleware"
	"github.com/stkrfx/poshak-attendance/internal/services"
)

func main() {
	cfg := config.LoadConfig()
	db := database.ConnectPostgres(cfg.DatabaseURL)

	emailSvc := services.NewEmailService(cfg)
	firebaseSvc, err := services.NewFirebaseAuthService(cfg)
	if err != nil {
		log.Printf("Warning: Firebase Admin SDK initialization issue: %v", err)
	}
	sheetsSvc := services.NewSheetsSyncService(db, cfg)

	// Background ticker for automatic Google Sheets synchronization
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = sheetsSvc.SyncAllActiveMonths(ctx)
		ticker := time.NewTicker(time.Duration(cfg.SheetSyncIntervalMinutes) * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = sheetsSvc.SyncAllActiveMonths(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()

	userAuthHandler := handlers.NewUserAuthHandler(db, cfg, firebaseSvc, emailSvc)
	userProfileHandler := handlers.NewUserProfileHandler(db, emailSvc)
	userAttendanceHandler := handlers.NewUserAttendanceHandler(db, sheetsSvc)
	userDocHandler := handlers.NewUserDocumentHandler(db)
	userSysHandler := handlers.NewUserSystemHandler(db)
	superHandler := handlers.NewSuperAdminHandler(db, cfg, sheetsSvc)

	mux := http.NewServeMux()

	// Health & Force-Update Check (Public)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
			Success: true,
			Message: "Poshak Backend is running.",
		})
	})
	mux.HandleFunc("GET /api/v1/system/version", userSysHandler.CheckAppVersion)

	// Employee Authentication Routes (Public)
	mux.HandleFunc("POST /api/v1/auth/login", userAuthHandler.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", userAuthHandler.RefreshToken)
	mux.HandleFunc("POST /api/v1/auth/forgot-password/email-otp", userAuthHandler.SendForgotPasswordEmailOTP)
	mux.HandleFunc("POST /api/v1/auth/reset-password", userAuthHandler.ResetPassword)

	// Employee Protected Routes
	userGuard := middleware.UserAuthMiddleware(db, cfg.UserJWTSecret)
	mux.Handle("GET /api/v1/profile", userGuard(http.HandlerFunc(userProfileHandler.GetProfile)))
	mux.Handle("PATCH /api/v1/profile", userGuard(http.HandlerFunc(userProfileHandler.UpdateProfile)))
	mux.Handle("POST /api/v1/profile/email/send-otp", userGuard(http.HandlerFunc(userProfileHandler.SendEmailVerificationOTP)))
	mux.Handle("POST /api/v1/profile/email/verify-otp", userGuard(http.HandlerFunc(userProfileHandler.VerifyEmailOTP)))
	mux.Handle("POST /api/v1/profile/change-password", userGuard(http.HandlerFunc(userProfileHandler.ChangePassword)))
	mux.Handle("GET /api/v1/profile/devices", userGuard(http.HandlerFunc(userProfileHandler.GetLoggedInDevices)))
	mux.Handle("POST /api/v1/profile/devices/send-otp", userGuard(http.HandlerFunc(userProfileHandler.SendDeviceLogoutOTP)))
	mux.Handle("POST /api/v1/profile/devices/logout-current", userGuard(http.HandlerFunc(userProfileHandler.LogoutCurrentDevice)))
	mux.Handle("POST /api/v1/profile/devices/logout-others", userGuard(http.HandlerFunc(userProfileHandler.LogoutAllOtherDevices)))
	mux.Handle("DELETE /api/v1/profile/devices/{session_id}", userGuard(http.HandlerFunc(userProfileHandler.LogoutSpecificDevice)))

	mux.Handle("GET /api/v1/attendance", userGuard(http.HandlerFunc(userAttendanceHandler.GetAttendance)))
	mux.Handle("GET /api/v1/documents", userGuard(http.HandlerFunc(userDocHandler.ListDocuments)))
	mux.Handle("POST /api/v1/documents", userGuard(http.HandlerFunc(userDocHandler.UploadDocument)))
	mux.Handle("DELETE /api/v1/documents/{id}", userGuard(http.HandlerFunc(userDocHandler.DeleteDocument)))
	mux.Handle("GET /api/v1/notifications", userGuard(http.HandlerFunc(userSysHandler.ListNotifications)))
	mux.Handle("POST /api/v1/notifications/read-all", userGuard(http.HandlerFunc(userSysHandler.MarkAllNotificationsRead)))

	// SuperUser (Admin & Developer) Routes
	mux.HandleFunc("POST /api/v1/super/setup", superHandler.BootstrapSuperUser)
	mux.HandleFunc("POST /api/v1/super/login", superHandler.SuperLogin)

	superGuard := middleware.SuperAuthMiddleware(db, cfg.SuperJWTSecret)
	mux.Handle("POST /api/v1/super/users", superGuard(http.HandlerFunc(superHandler.CreateEmployee)))
	mux.Handle("GET /api/v1/super/users", superGuard(http.HandlerFunc(superHandler.ListEmployees)))
	mux.Handle("PATCH /api/v1/super/users/{user_id}/block", superGuard(http.HandlerFunc(superHandler.BlockEmployee)))
	mux.Handle("PATCH /api/v1/super/users/{user_id}/unblock", superGuard(http.HandlerFunc(superHandler.UnblockEmployee)))
	mux.Handle("PATCH /api/v1/super/users/{user_id}/moderation", superGuard(http.HandlerFunc(superHandler.ModerateEmployee)))
	mux.Handle("POST /api/v1/super/attendance/sync", superGuard(http.HandlerFunc(superHandler.TriggerSheetsSync)))
	mux.Handle("POST /api/v1/super/notifications", superGuard(http.HandlerFunc(superHandler.SendNotification)))
	mux.Handle("POST /api/v1/super/releases", superGuard(http.HandlerFunc(superHandler.PublishAppRelease)))

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      enableCORS(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Poshak Go Backend listening on port %s...", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down Poshak Go Backend gracefully...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
