package services

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/stkrfx/poshak-attendance/internal/config"
)

type EmailService struct {
	cfg        *config.Config
	httpClient *http.Client
}

func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
	}
}

func (s *EmailService) SendOTP(toEmail, otpCode, purpose string) error {
	startTime := time.Now()

	if s.cfg.Env == "development" {
		log.Printf("[EMAIL-SERVICE] [DEV-MODE] Generated 6-digit OTP for %s (%s): %s", toEmail, purpose, otpCode)
	}

	subject := "Your Poshak Verification Code"
	actionText := "verify your email address"
	if purpose == "RESET_PASSWORD" {
		subject = "Poshak Password Reset Code"
		actionText = "reset your account password"
	}

	plainBody := fmt.Sprintf(
		"Hello,\n\n"+
			"Use the following 6-digit verification code to %s:\n\n"+
			"%s\n\n"+
			"This code expires in 10 minutes.\n\n"+
			"- Poshak Team\n",
		actionText, otpCode,
	)

	// 1. Primary path for Render Free Tier: HTTPS Webhook (Port 443, never blocked by Render)
	if strings.TrimSpace(s.cfg.EmailWebhookURL) != "" {
		log.Printf("[EMAIL-SERVICE] Sending %s OTP to=%s via HTTPS Webhook (Port 443)...", purpose, toEmail)
		payload, _ := json.Marshal(map[string]string{
			"to":      toEmail,
			"subject": subject,
			"body":    plainBody,
		})

		resp, err := s.httpClient.Post(s.cfg.EmailWebhookURL, "application/json", bytes.NewBuffer(payload))
		if err != nil {
			log.Printf("[EMAIL-SERVICE] ERROR: HTTPS Webhook request failed after %v: %v", time.Since(startTime), err)
			return err
		}
		defer resp.Body.Close()
		respBytes, _ := io.ReadAll(resp.Body)

		if resp.StatusCode >= 400 {
			log.Printf("[EMAIL-SERVICE] ERROR: HTTPS Webhook returned HTTP %d: %s", resp.StatusCode, string(respBytes))
			return fmt.Errorf("email webhook returned status %d", resp.StatusCode)
		}

		log.Printf("[EMAIL-SERVICE] SUCCESS: OTP delivered to=%s via HTTPS Webhook in %v (response=%s)",
			toEmail, time.Since(startTime), strings.TrimSpace(string(respBytes)))
		return nil
	}

	// 2. Fallback path (Local Dev or Paid Render Plan): Direct SMTP with strict 10-second timeout
	log.Printf("[SMTP-SERVICE] Preparing to send %s OTP to=%s via host=%s:%s (from=%s)",
		purpose, toEmail, s.cfg.SMTPHost, s.cfg.SMTPPort, s.cfg.SMTPEmail)

	if s.cfg.SMTPEmail == "" || s.cfg.SMTPAppPassword == "" {
		log.Printf("[SMTP-SERVICE] ERROR: SMTP_EMAIL or SMTP_APP_PASSWORD is empty!")
		return fmt.Errorf("SMTP credentials are not configured")
	}

	addr := fmt.Sprintf("%s:%s", s.cfg.SMTPHost, s.cfg.SMTPPort)
	log.Printf("[SMTP-SERVICE] Dialing SMTP server %s with 10s timeout...", addr)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Printf("[SMTP-SERVICE] ERROR: TCP connection to %s timed out or was blocked after %v: %v (Hint: Render Free Tier blocks ports 25/465/587. Set EMAIL_WEBHOOK_URL in Render env!)",
			addr, time.Since(startTime), err)
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		log.Printf("[SMTP-SERVICE] ERROR: Failed to create SMTP client: %v", err)
		return err
	}
	defer client.Quit()

	tlsConfig := &tls.Config{ServerName: s.cfg.SMTPHost}
	if err := client.StartTLS(tlsConfig); err != nil {
		log.Printf("[SMTP-SERVICE] ERROR: StartTLS failed: %v", err)
		return err
	}

	auth := smtp.PlainAuth("", s.cfg.SMTPEmail, s.cfg.SMTPAppPassword, s.cfg.SMTPHost)
	if err := client.Auth(auth); err != nil {
		log.Printf("[SMTP-SERVICE] ERROR: Gmail SMTP authentication failed: %v", err)
		return err
	}

	if err := client.Mail(s.cfg.SMTPEmail); err != nil {
		return err
	}
	if err := client.Rcpt(toEmail); err != nil {
		return err
	}

	wc, err := client.Data()
	if err != nil {
		return err
	}

	rawMsg := fmt.Sprintf(
		"From: Poshak <%s>\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"+
			"%s",
		s.cfg.SMTPEmail, toEmail, subject, plainBody,
	)

	if _, err := wc.Write([]byte(rawMsg)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}

	log.Printf("[SMTP-SERVICE] SUCCESS: 6-digit OTP email delivered to=%s in %v", toEmail, time.Since(startTime))
	return nil
}
