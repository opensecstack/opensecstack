package email

import (
	"fmt"
	"log"
	"net/smtp"
)

// Config holds SMTP configuration for sending emails.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	SiteURL  string // e.g. "https://sin.to" — used to build reset links
}

// Mailer sends transactional emails.
type Mailer struct{ cfg Config }

// New creates a new Mailer with the given configuration.
func New(cfg Config) *Mailer {
	return &Mailer{cfg: cfg}
}

// SendPasswordReset sends a password reset email to toAddr containing the reset token link.
// recipientName is used to personalise the greeting ("Hi Alice," vs "Hi there,").
// If cfg.Host is empty (not configured), the token is logged to stdout instead (dev mode fallback).
func (m *Mailer) SendPasswordReset(toAddr, token, recipientName string) error {
	if m.cfg.Host == "" {
		log.Printf("[email] password reset token for %s: %s", toAddr, token)
		return nil
	}

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", m.cfg.SiteURL, token)
	subject, body := RenderPasswordResetEmail(resetURL, recipientName, m.cfg.SiteURL)
	return m.SendHTML(toAddr, subject, body)
}

// SendNewComment notifies a post author that someone commented on their post.
func (m *Mailer) SendNewComment(toAddr, toUsername, actorUsername, postTitle, postSlug string) error {
	if m.cfg.Host == "" {
		log.Printf("[email] new comment: to=%s actor=%s post=%q", toAddr, actorUsername, postTitle)
		return nil
	}
	subject, body := RenderCommentEmail(actorUsername, postTitle, postSlug, "", toUsername, m.cfg.SiteURL)
	return m.SendHTML(toAddr, subject, body)
}

// SendNewReaction notifies a post author that someone reacted to their post.
func (m *Mailer) SendNewReaction(toAddr, toUsername, actorUsername, reactionKind, postTitle, postSlug string) error {
	if m.cfg.Host == "" {
		log.Printf("[email] new reaction: to=%s actor=%s kind=%s post=%q", toAddr, actorUsername, reactionKind, postTitle)
		return nil
	}
	subject, body := RenderReactionEmail(actorUsername, reactionKind, postTitle, postSlug, toUsername, m.cfg.SiteURL)
	return m.SendHTML(toAddr, subject, body)
}

// SendNewFollower notifies a user that someone started following them.
func (m *Mailer) SendNewFollower(toAddr, toUsername, actorUsername string) error {
	if m.cfg.Host == "" {
		log.Printf("[email] new follower: to=%s actor=%s", toAddr, actorUsername)
		return nil
	}
	subject, body := RenderFollowEmail(actorUsername, toUsername, m.cfg.SiteURL)
	return m.SendHTML(toAddr, subject, body)
}

// SendMention notifies a user that they were mentioned in a comment.
func (m *Mailer) SendMention(toAddr, toUsername, actorUsername, postTitle, postSlug string) error {
	if m.cfg.Host == "" {
		log.Printf("[email] mention: to=%s actor=%s post=%q", toAddr, actorUsername, postTitle)
		return nil
	}
	_, body := RenderCommentEmail(actorUsername, postTitle, postSlug, "", toUsername, m.cfg.SiteURL)
	subject := fmt.Sprintf("%s mentioned you in a comment on \"%s\"", actorUsername, postTitle)
	return m.SendHTML(toAddr, subject, body)
}

// SendEmailVerification sends an email verification link to toAddr.
// If cfg.Host is empty (not configured), the token is logged to stdout instead (dev mode fallback).
func (m *Mailer) SendEmailVerification(toAddr, username, token string) error {
	if m.cfg.Host == "" {
		log.Printf("[email] verify token for %s: %s", toAddr, token)
		return nil
	}
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", m.cfg.SiteURL, token)
	subject, body := RenderVerificationEmail(verifyURL, username, m.cfg.SiteURL)
	return m.SendHTML(toAddr, subject, body)
}

// SendHTML sends an HTML email to toAddr with the given subject and HTML body.
// If cfg.Host is empty (not configured), the email is logged to stdout instead (dev mode fallback).
func (m *Mailer) SendHTML(toAddr, subject, body string) error {
	if m.cfg.Host == "" {
		log.Printf("[email] html email: to=%s subject=%q", toAddr, subject)
		return nil
	}
	serverAddr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		m.cfg.From, toAddr, subject, body,
	)
	return smtp.SendMail(serverAddr, auth, m.cfg.From, []string{toAddr}, []byte(msg))
}

// DigestPost holds the data for a single post entry in the weekly digest email.
type DigestPost struct {
	Title          string
	Slug           string
	AuthorUsername string
	ReactionCount  int
	ViewCount      int
	Excerpt        string
}

// SendWeeklyDigest sends the weekly top-posts digest email to a single recipient.
// If cfg.Host is empty (dev mode), the digest is logged to stdout instead.
func (m *Mailer) SendWeeklyDigest(to, username, siteURL string, posts []DigestPost) error {
	if m.cfg.Host == "" {
		log.Printf("[email] weekly digest: to=%s posts=%d", to, len(posts))
		return nil
	}
	subject, htmlBody := RenderDigestEmail(posts, username, siteURL)
	return m.SendHTML(to, subject, htmlBody)
}
