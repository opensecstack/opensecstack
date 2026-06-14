package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/opensecstack/community/internal/auth"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_]{3,30}$`)

func Register(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username   string `json:"username"`
			Email      string `json:"email"`
			Password   string `json:"password"`
			InviteCode string `json:"invite_code"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		// Validate username
		if !usernameRe.MatchString(req.Username) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username must be 3-30 alphanumeric characters or underscores"})
			return
		}

		// Validate email using net/mail for RFC-compliant parsing.
		parsed, err := mail.ParseAddress(req.Email)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid email address"})
			return
		}
		// Require a domain part that contains a dot (rejects user@localhost etc.).
		atIdx := strings.LastIndex(parsed.Address, "@")
		if atIdx < 0 || !strings.Contains(parsed.Address[atIdx+1:], ".") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid email address"})
			return
		}

		// Validate password
		if len(req.Password) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
			return
		}

		// Invite-only check
		if d.Cfg.InviteOnly && req.InviteCode == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invite code required"})
			return
		}

		// Validate invite code if provided
		var inviteID string
		if req.InviteCode != "" {
			var used bool
			var expired bool
			err := d.Pool.QueryRow(r.Context(),
				`SELECT id, used_at IS NOT NULL, expires_at < now() FROM invites WHERE code=$1`,
				req.InviteCode,
			).Scan(&inviteID, &used, &expired)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invite code not found"})
				return
			}
			if used {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "invite code already used"})
				return
			}
			if expired {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invite code expired"})
				return
			}
		}

		// Email domain whitelist check
		if len(d.Cfg.AllowedEmailDomains) > 0 {
			domain := strings.ToLower(req.Email[strings.LastIndex(req.Email, "@")+1:])
			allowed := false
			for _, d := range d.Cfg.AllowedEmailDomains {
				if strings.ToLower(strings.TrimSpace(d)) == domain {
					allowed = true
					break
				}
			}
			if !allowed {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "email domain not allowed on this platform"})
				return
			}
		}

		// Hash password with bcrypt (cost 12, self-salting — no pepper needed).
		hash, err := bcryptHash(req.Password)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash password"})
			return
		}

		// Insert user
		var newUserID string
		err = d.Pool.QueryRow(r.Context(),
			`INSERT INTO users (username, email, password_hash, role) VALUES ($1,$2,$3,'author') RETURNING id`,
			req.Username, req.Email, hash,
		).Scan(&newUserID)
		if err != nil {
			if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "username or email already taken"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
			return
		}

		// Mark invite as used
		if req.InviteCode != "" {
			_, _ = d.Pool.Exec(r.Context(),
				`UPDATE invites SET used_by=$1, used_at=now() WHERE code=$2`,
				newUserID, req.InviteCode,
			)
		}

		// Generate email verification token and store it.
		verifyToken, err := func() (string, error) {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return "", err
			}
			return hex.EncodeToString(b), nil
		}()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate verification token"})
			return
		}
		_, err = d.Pool.Exec(r.Context(),
			`INSERT INTO email_verify_tokens (user_id, token, expires_at)
			 VALUES ($1, $2, now() + interval '24 hours')`,
			newUserID, verifyToken,
		)
		if err != nil {
			// Non-fatal: user can request a resend later.
			log.Printf("[register] failed to insert email verify token for user %s: %v", newUserID, err)
		}

		// Send verification email in background (never use request context in goroutine).
		if d.Mailer != nil {
			go func(toAddr, username, tok string) {
				if err := d.Mailer.SendEmailVerification(toAddr, username, tok); err != nil {
					log.Printf("[register] failed to send verification email to %s: %v", toAddr, err)
				}
			}(req.Email, req.Username, verifyToken)
		}

		// Issue JWT
		tok, claims, err := auth.Issue(d.Cfg.JWTSecret, d.Cfg.JWTIssuer, req.Username, "author", d.Cfg.TokenTTL)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
			return
		}

		// Record session so the session-revocation middleware accepts the new token immediately.
		recordSession(r, d, newUserID, tok, claims.ExpiresAt.Time)

		// Send a welcome notification.
		d.Pool.Exec(r.Context(),
			`INSERT INTO notifications (user_id, type) VALUES ($1, 'welcome')`,
			newUserID,
		)

		writeJSON(w, http.StatusCreated, map[string]any{
			"token":          tok,
			"role":           "author",
			"sub":            req.Username,
			"expires_at":     claims.ExpiresAt.Time.Format(time.RFC3339),
			"email_verified": false,
		})
	}
}
