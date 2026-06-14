package email

import (
	"fmt"
	"net/smtp"
)

type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	SiteURL  string
}

type Mailer struct {
	cfg Config
}

func New(cfg Config) *Mailer { return &Mailer{cfg: cfg} }

func (m *Mailer) SendVerification(to, username, token string) error {
	link := m.cfg.SiteURL + "/verify-email?token=" + token
	body := fmt.Sprintf("Hi %s,\n\nVerify your email: %s\n\nExpires in 24 hours.", username, link)
	return m.send(to, "Verify your SIN account", body)
}

func (m *Mailer) SendPasswordReset(to, token string) error {
	link := m.cfg.SiteURL + "/reset-password?token=" + token
	body := fmt.Sprintf("Reset your password: %s\n\nExpires in 1 hour.", link)
	return m.send(to, "Reset your SIN password", body)
}

func (m *Mailer) send(to, subject, body string) error {
	if m.cfg.Host == "" {
		return nil // dev mode — skip sending
	}
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		m.cfg.From, to, subject, body)
	return smtp.SendMail(addr, auth, m.cfg.From, []string{to}, []byte(msg))
}
