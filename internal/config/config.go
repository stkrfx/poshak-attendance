package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Port                        string
	Env                         string
	Timezone                    string
	DatabaseURL                 string
	UserJWTSecret               string
	SuperJWTSecret              string
	SuperSetupSecret            string
	GoogleSpreadsheetID         string
	GoogleSheetsCredentialsJSON string
	SheetSyncIntervalMinutes    int
	FirebaseServiceAccountJSON  string
	SMTPHost                    string
	SMTPPort                    string
	SMTPEmail                   string
	SMTPAppPassword             string
	EmailWebhookURL             string
}

func LoadConfig() *Config {
	_ = godotenv.Load()

	syncMinutes, err := strconv.Atoi(getEnv("SHEET_SYNC_INTERVAL_MINUTES", "15"))
	if err != nil || syncMinutes <= 0 {
		syncMinutes = 15
	}

	cfg := &Config{
		Port:                        getEnv("PORT", "8080"),
		Env:                         getEnv("ENV", "development"),
		Timezone:                    getEnv("TIMEZONE", "Asia/Kolkata"),
		DatabaseURL:                 getEnv("DATABASE_URL", ""),
		UserJWTSecret:               getEnv("USER_JWT_SECRET", ""),
		SuperJWTSecret:              getEnv("SUPER_JWT_SECRET", ""),
		SuperSetupSecret:            getEnv("SUPER_SETUP_SECRET", ""),
		GoogleSpreadsheetID:         getEnv("GOOGLE_SPREADSHEET_ID", ""),
		GoogleSheetsCredentialsJSON: getEnv("GOOGLE_SHEETS_CREDENTIALS_JSON", ""),
		SheetSyncIntervalMinutes:    syncMinutes,
		FirebaseServiceAccountJSON:  getEnv("FIREBASE_SERVICE_ACCOUNT_JSON", ""),
		SMTPHost:                    getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:                    getEnv("SMTP_PORT", "587"),
		SMTPEmail:                   getEnv("SMTP_EMAIL", ""),
		SMTPAppPassword:             getEnv("SMTP_APP_PASSWORD", ""),
		EmailWebhookURL:             getEnv("EMAIL_WEBHOOK_URL", ""),
	}

	if cfg.DatabaseURL == "" {
		log.Fatal("CRITICAL: DATABASE_URL environment variable is required")
	}
	if cfg.UserJWTSecret == "" || cfg.SuperJWTSecret == "" {
		log.Fatal("CRITICAL: USER_JWT_SECRET and SUPER_JWT_SECRET environment variables are required")
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if val, exists := os.LookupEnv(key); exists && val != "" {
		return val
	}
	return fallback
}
