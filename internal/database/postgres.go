package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/stkrfx/poshak-attendance/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func ConnectPostgres(databaseURL string) *gorm.DB {
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             2 * time.Second,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true,
			Colorful:                  true,
		},
	)

	// PreferSimpleProtocol: true disables implicit prepared statement caching,
	// preventing SQLSTATE 0A000 ("cached plan must not change result type") on Neon PostgreSQL.
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  databaseURL,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		Logger: newLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		log.Fatalf("CRITICAL: Failed to connect to Neon PostgreSQL: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("CRITICAL: Failed to get generic database handle: %v", err)
	}
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	err = db.AutoMigrate(
		&models.User{},
		&models.SuperUser{},
		&models.DeviceSession{},
		&models.MonthlyAttendanceSummary{},
		&models.AttendanceRecord{},
		&models.UserDocument{},
		&models.Notification{},
		&models.AppRelease{},
		&models.EmailOTP{},
	)
	if err != nil {
		log.Fatalf("CRITICAL: AutoMigrate failed: %v", err)
	}

	// Migrate the legacy username permission to the new profile permission.
	// Use a fresh session so Transaction starts with an initialized Statement.
	// This avoids a nil Statement panic in GORM v1.31.x on the root handle.
	err = db.Session(&gorm.Session{NewDB: true}).Transaction(func(tx *gorm.DB) error {
		var legacyColumnExists bool
		if err := tx.Raw(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = current_schema()
				  AND table_name = 'users'
				  AND column_name = 'can_edit_username'
			)
		`).Scan(&legacyColumnExists).Error; err != nil {
			return fmt.Errorf("check legacy username permission column: %w", err)
		}

		if !legacyColumnExists {
			// Already migrated, or this is a fresh database.
			return nil
		}

		var profileColumnExists bool
		if err := tx.Raw(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = current_schema()
				  AND table_name = 'users'
				  AND column_name = 'can_edit_profile'
			)
		`).Scan(&profileColumnExists).Error; err != nil {
			return fmt.Errorf("check profile permission column: %w", err)
		}
		if !profileColumnExists {
			return fmt.Errorf("can_edit_profile column is missing after AutoMigrate")
		}

		if err := tx.Exec(`
			UPDATE users SET can_edit_profile = can_edit_username
		`).Error; err != nil {
			return fmt.Errorf("copy legacy profile permissions: %w", err)
		}

		if err := tx.Exec(`
			ALTER TABLE users DROP COLUMN can_edit_username
		`).Error; err != nil {
			return fmt.Errorf("drop legacy username permission: %w", err)
		}

		return nil
	})
	if err != nil {
		log.Fatalf("CRITICAL: Profile permission migration failed: %v", err)
	}

	log.Println("Connected to Neon PostgreSQL & verified schema migrations successfully.")
	return db
}
