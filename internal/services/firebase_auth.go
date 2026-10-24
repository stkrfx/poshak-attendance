package services

import (
	"context"
	"errors"
	"strings"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/stkrfx/poshak-attendance/internal/config"
	"google.golang.org/api/option"
)

type FirebaseAuthService struct {
	client *auth.Client
}

// NewFirebaseAuthService initializes Firebase Admin SDK strictly from the FIREBASE_SERVICE_ACCOUNT_JSON env variable.
func NewFirebaseAuthService(cfg *config.Config) (*FirebaseAuthService, error) {
	if strings.TrimSpace(cfg.FirebaseServiceAccountJSON) == "" {
		return &FirebaseAuthService{client: nil}, nil
	}

	ctx := context.Background()
	opt := option.WithCredentialsJSON([]byte(cfg.FirebaseServiceAccountJSON))
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return nil, err
	}

	authClient, err := app.Auth(ctx)
	if err != nil {
		return nil, err
	}

	return &FirebaseAuthService{client: authClient}, nil
}

// VerifyPhoneIDToken verifies a Firebase ID token obtained after SMS OTP verification on Android
// and returns the normalized 10-digit Indian mobile number.
func (f *FirebaseAuthService) VerifyPhoneIDToken(ctx context.Context, idToken string) (string, error) {
	if f.client == nil {
		return "", errors.New("Firebase service account JSON is not configured")
	}

	token, err := f.client.VerifyIDToken(ctx, idToken)
	if err != nil {
		return "", err
	}

	phoneRaw, ok := token.Claims["phone_number"].(string)
	if !ok || phoneRaw == "" {
		return "", errors.New("verified Firebase token does not contain a phone_number claim")
	}

	normalized := strings.TrimPrefix(phoneRaw, "+91")
	normalized = strings.TrimSpace(normalized)
	return normalized, nil
}
