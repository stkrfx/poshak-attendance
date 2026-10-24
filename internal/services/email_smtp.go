package services

import (
	"fmt"
	"net/smtp"

	"github.com/stkrfx/poshak-attendance/internal/config"
)

type EmailService struct {
	cfg *config.Config
}

func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{cfg: cfg}
}

func (s *EmailService) SendOTP(toEmail, otpCode, purpose string) error {
	if s.cfg.SMTPEmail == "" || s.cfg.SMTPAppPassword == "" {
		return fmt.Errorf("SMTP credentials are not configured in environment variables")
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
	return smtp.SendMail(addr, auth, s.cfg.SMTPEmail, []string{toEmail}, []byte(body))
}
