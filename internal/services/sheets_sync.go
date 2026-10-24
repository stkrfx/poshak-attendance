package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/stkrfx/poshak-attendance/internal/config"
	"github.com/stkrfx/poshak-attendance/internal/models"
	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type SheetsSyncService struct {
	db  *gorm.DB
	cfg *config.Config
	mu  sync.Mutex // Prevents overlapping sync jobs from colliding
}

func NewSheetsSyncService(db *gorm.DB, cfg *config.Config) *SheetsSyncService {
	return &SheetsSyncService{db: db, cfg: cfg}
}

// ActiveMonthNames returns the current month and previous 2 months formatted like "Oct 2026", "Sep 2026", "Aug 2026".
func (s *SheetsSyncService) ActiveMonthNames() []string {
	loc, err := time.LoadLocation(s.cfg.Timezone)
	if err != nil {
		loc = time.FixedZone("IST", 5*3600+1800)
	}
	now := time.Now().In(loc)
	firstOfCurrent := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)

	return []string{
		firstOfCurrent.Format("Jan 2006"),
		firstOfCurrent.AddDate(0, -1, 0).Format("Jan 2006"),
		firstOfCurrent.AddDate(0, -2, 0).Format("Jan 2006"),
	}
}

// SyncAllActiveMonths pulls pre-calculated summary values (Columns B-F) and daily cells + notes (Columns G-AK)
// and performs fast bulk upserts into PostgreSQL.
func (s *SheetsSyncService) SyncAllActiveMonths(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(s.cfg.GoogleSheetsCredentialsJSON) == "" || strings.TrimSpace(s.cfg.GoogleSpreadsheetID) == "" {
		log.Println("Skipping Google Sheets sync: GOOGLE_SHEETS_CREDENTIALS_JSON or GOOGLE_SPREADSHEET_ID not set.")
		return nil
	}

	srv, err := sheets.NewService(ctx, option.WithCredentialsJSON([]byte(s.cfg.GoogleSheetsCredentialsJSON)))
	if err != nil {
		return fmt.Errorf("failed to initialize Google Sheets client: %w", err)
	}

	// Load all employees once into a lookup map by their unique Google Sheet Name (Column A)
	var users []models.User
	if err := s.db.WithContext(ctx).Find(&users).Error; err != nil {
		return fmt.Errorf("failed to load employees from database: %w", err)
	}
	if len(users) == 0 {
		log.Println("Google Sheets sync skipped: no employees exist in the users table yet.")
		return nil
	}

	userByName := make(map[string]models.User, len(users))
	for _, u := range users {
		userByName[strings.TrimSpace(u.Name)] = u
	}

	for _, monthSheet := range s.ActiveMonthNames() {
		if err := s.syncSingleMonthSheet(ctx, srv, monthSheet, userByName); err != nil {
			log.Printf("Warning: could not sync sheet '%s': %v", monthSheet, err)
		}
	}
	return nil
}

func (s *SheetsSyncService) syncSingleMonthSheet(
	ctx context.Context,
	srv *sheets.Service,
	monthSheetName string,
	userByName map[string]models.User,
) error {
	loc, err := time.LoadLocation(s.cfg.Timezone)
	if err != nil {
		loc = time.FixedZone("IST", 5*3600+1800)
	}
	todayStr := time.Now().In(loc).Format("2006-01-02")

	parsedMonth, err := time.ParseInLocation("Jan 2006", monthSheetName, loc)
	if err != nil {
		return fmt.Errorf("invalid month sheet name %s: %w", monthSheetName, err)
	}

	readRange := fmt.Sprintf("'%s'!A1:AK200", monthSheetName)
	resp, err := srv.Spreadsheets.Get(s.cfg.GoogleSpreadsheetID).
		Ranges(readRange).
		IncludeGridData(true).
		Context(ctx).
		Do()
	if err != nil {
		return err
	}

	if len(resp.Sheets) == 0 || len(resp.Sheets[0].Data) == 0 {
		return nil
	}

	gridData := resp.Sheets[0].Data[0]
	if len(gridData.RowData) < 3 {
		return nil
	}

	var summariesBatch []models.MonthlyAttendanceSummary
	var recordsBatch []models.AttendanceRecord
	nowUTC := time.Now().UTC()
	daysInMonth := time.Date(parsedMonth.Year(), parsedMonth.Month()+1, 0, 0, 0, 0, 0, loc).Day()

	// Row 1 & Row 2 are headers (indices 0 and 1). Employee rows start at Row 3 (index 2).
	for rowIdx := 2; rowIdx < len(gridData.RowData); rowIdx++ {
		row := gridData.RowData[rowIdx]
		if row == nil || len(row.Values) < 6 {
			continue
		}

		empName := strings.TrimSpace(cellFormattedValue(row.Values, 0))
		if empName == "" {
			continue
		}

		user, exists := userByName[empName]
		if !exists {
			continue
		}

		// Collect Columns B, C, D, E, F summary row
		summariesBatch = append(summariesBatch, models.MonthlyAttendanceSummary{
			UserID:         user.ID,
			MonthSheetName: monthSheetName,
			SundayModeS:    defaultString(cellFormattedValue(row.Values, 1), "F"),
			TotalPresentP:  defaultString(cellFormattedValue(row.Values, 2), "0"),
			TotalAbsentA:   defaultString(cellFormattedValue(row.Values, 3), "0"),
			TotalPayableG:  defaultString(cellFormattedValue(row.Values, 4), "0"),
			TotalPaidT:     defaultString(cellFormattedValue(row.Values, 5), "0"),
			SyncedAt:       nowUTC,
		})

		// Collect Daily Columns G to AK (indices 6 to 36 -> Days 1 to 31)
		for dayNum := 1; dayNum <= daysInMonth; dayNum++ {
			colIdx := 5 + dayNum // Day 1 is index 6 (Column G)
			dateObj := time.Date(parsedMonth.Year(), parsedMonth.Month(), dayNum, 0, 0, 0, 0, loc)
			dateStr := dateObj.Format("2006-01-02")

			if dateStr > todayStr {
				continue
			}

			rawVal := strings.ToUpper(strings.TrimSpace(cellFormattedValue(row.Values, colIdx)))
			isGreyed := isCellDarkGrey(row.Values, colIdx)
			noteText := strings.TrimSpace(cellNote(row.Values, colIdx))

			var status string
			switch {
			case rawVal == "P":
				status = "P"
			case rawVal == "A":
				status = "A"
			case rawVal == "H":
				status = "H"
			case dateStr == todayStr && rawVal == "":
				status = "UNMARKED"
			case isGreyed || (dateStr < todayStr && rawVal == ""):
				status = "NA"
			default:
				status = "NA"
			}

			var notePtr *string
			if noteText != "" {
				noteVal := noteText
				notePtr = &noteVal
			}

			recordsBatch = append(recordsBatch, models.AttendanceRecord{
				UserID:         user.ID,
				AttendanceDate: dateStr,
				MonthSheetName: monthSheetName,
				Status:         status,
				Note:           notePtr,
			})
		}
	}

	// Bulk Upsert Monthly Summaries in a single batch query
	if len(summariesBatch) > 0 {
		if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}, {Name: "month_sheet_name"}},
			DoUpdates: clause.AssignmentColumns([]string{"sunday_mode_s", "total_present_p", "total_absent_a", "total_payable_g", "total_paid_t", "synced_at"}),
		}).CreateInBatches(&summariesBatch, 100).Error; err != nil {
			return fmt.Errorf("failed bulk upsert for summaries (%s): %w", monthSheetName, err)
		}
	}

	// Bulk Upsert Daily Attendance Records in batches of 250 rows
	if len(recordsBatch) > 0 {
		if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}, {Name: "attendance_date"}},
			DoUpdates: clause.AssignmentColumns([]string{"month_sheet_name", "status", "note"}),
		}).CreateInBatches(&recordsBatch, 250).Error; err != nil {
			return fmt.Errorf("failed bulk upsert for daily records (%s): %w", monthSheetName, err)
		}
	}

	log.Printf("Synced sheet '%s': %d employee summaries, %d daily records.", monthSheetName, len(summariesBatch), len(recordsBatch))
	return nil
}

func cellFormattedValue(cells []*sheets.CellData, idx int) string {
	if idx >= len(cells) || cells[idx] == nil {
		return ""
	}
	return cells[idx].FormattedValue
}

func cellNote(cells []*sheets.CellData, idx int) string {
	if idx >= len(cells) || cells[idx] == nil {
		return ""
	}
	return cells[idx].Note
}

func isCellDarkGrey(cells []*sheets.CellData, idx int) bool {
	if idx >= len(cells) || cells[idx] == nil || cells[idx].EffectiveFormat == nil || cells[idx].EffectiveFormat.BackgroundColor == nil {
		return false
	}
	bg := cells[idx].EffectiveFormat.BackgroundColor
	if bg.Red > 0.2 && bg.Red < 0.85 &&
		absDiff(bg.Red, bg.Green) < 0.05 &&
		absDiff(bg.Green, bg.Blue) < 0.05 {
		return true
	}
	return false
}

func absDiff(a, b float64) float64 {
	if a > b {
		return a - b
	}
	return b - a
}

func defaultString(val, fallback string) string {
	if strings.TrimSpace(val) == "" {
		return fallback
	}
	return strings.TrimSpace(val)
}
