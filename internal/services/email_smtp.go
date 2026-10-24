package services

import (
	"fmt"
	"log"
	"net/smtp"
	"time"

	"github.com/stkrfx/poshak-attendance/internal/config"
)

type EmailService struct {
	cfg *config.Config
}

func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{cfg: cfg}
}

func (s *EmailService) SendOTP(toEmail, otpCode, purpose string) error {
	startTime := time.Now()
	log.Printf("[SMTP-SERVICE] Preparing to send %s OTP to=%s via host=%s:%s (from=%s)",
		purpose, toEmail, s.cfg.SMTPHost, s.cfg.SMTPPort, s.cfg.SMTPEmail)

	if s.cfg.SMTPEmail == "" || s.cfg.SMTPAppPassword == "" {
		log.Printf("[SMTP-SERVICE] ERROR: SMTP_EMAIL or SMTP_APP_PASSWORD is empty in environment variables!")
		return fmt.Errorf("SMTP credentials are not configured in environment variables")
	}

	// In development mode, print the OTP in server logs for quick debugging
	if s.cfg.Env == "development" {
		log.Printf("[SMTP-SERVICE] [DEV-MODE] Generated 6-digit OTP for %s (%s): %s", toEmail, purpose, otpCode)
	}

	subject := "Your Poshak Verification Code"
	actionText := "verify your email address"
	if purpose == "RESET_PASSWORD" {
		subject = "Poshak Password Reset Code"
		actionText = "reset your account password"
	}

	body := fmt.Sprintf(
		"From: Poshak <%s>\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"+
			"Hello,\r\n\r\n"+
			"Use the following 6-digit verification code to %s:\r\n\r\n"+
			"%s\r\n\r\n"+
			"This code expires in 10 minutes.\r\n\r\n"+
			"- Poshak Team\r\n",
		s.cfg.SMTPEmail, toEmail, subject, actionText, otpCode,
	)

	auth := smtp.PlainAuth("", s.cfg.SMTPEmail, s.cfg.SMTPAppPassword, s.cfg.SMTPHost)
	addr := fmt.Sprintf("%s:%s", s.cfg.SMTPHost, s.cfg.SMTPPort)

	log.Printf("[SMTP-SERVICE] Dialing SMTP server %s...", addr)
	if err := smtp.SendMail(addr, auth, s.cfg.SMTPEmail, []string{toEmail}, []byte(body)); err != nil {
		log.Printf("[SMTP-SERVICE] ERROR: Failed to send OTP email to=%s after %v: %v",
			toEmail, time.Since(startTime), err)
		return err
	}

	log.Printf("[SMTP-SERVICE] SUCCESS: 6-digit OTP email delivered to=%s in %v",
		toEmail, time.Since(startTime))
	return nil
}
