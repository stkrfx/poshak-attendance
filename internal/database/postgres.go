package database

import (
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

	log.Println("Connected to Neon PostgreSQL & verified schema migrations successfully.")
	return db
}
