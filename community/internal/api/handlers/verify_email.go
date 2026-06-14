package handlers

// Wire in server.go:
//   mux.HandleFunc("GET /api/v1/auth/verify-email", handlers.VerifyEmail(d))
//   mux.Handle("POST /api/v1/auth/resend-verification", auth(http.HandlerFunc(handlers.ResendVerification(d))))

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

// VerifyEmail handles GET /api/v1/auth/verify-email?token=...
// It validates the token and marks the user's email as verified.
// No authentication required — the token itself is the credential.
func VerifyEmail(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid or expired verification token."})
			return
		}

		// Look up token: must exist, not used, not expired.
		var userID string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT user_id FROM email_verify_tokens
			 WHERE token = $1 AND used = false AND expires_at > now()`,
			token,
		).Scan(&userID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid or expired verification token."})
			return
		}

		// Mark the user's email as verified.
		_, err = d.Pool.Exec(r.Context(),
			`UPDATE users SET email_verified = true WHERE id = $1`,
			userID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify email"})
			return
		}

		// Mark the token as used.
		_, _ = d.Pool.Exec(r.Context(),
			`UPDATE email_verify_tokens SET used = true WHERE token = $1`,
			token,
		)

		writeJSON(w, http.StatusOK, map[string]string{"message": "Email verified successfully."})
	}
}

// ResendVerification handles POST /api/v1/auth/resend-verification (auth required).
// It generates a new verification token and sends it to the authenticated user's email.
func ResendVerification(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		// Fetch current verification status and email for the user.
		var userID, email string
		var emailVerified bool
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id, COALESCE(email,''), COALESCE(email_verified, false) FROM users WHERE username = $1`,
			claims.Sub,
		).Scan(&userID, &email, &emailVerified)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "user not found"})
			return
		}

		if emailVerified {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Already verified."})
			return
		}

		// Delete existing unused tokens for this user to keep the table clean.
		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM email_verify_tokens WHERE user_id = $1 AND used = false`,
			userID,
		)

		// Generate a new 32-byte crypto-random hex token.
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate token"})
			return
		}
		newToken := hex.EncodeToString(b)

		// Insert the new token.
		_, err = d.Pool.Exec(r.Context(),
			`INSERT INTO email_verify_tokens (user_id, token, expires_at)
			 VALUES ($1, $2, now() + interval '24 hours')`,
			userID, newToken,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create verification token"})
			return
		}

		// Send the verification email in background (never use the request context in goroutines).
		if d.Mailer != nil {
			go func(toAddr, username, tok string) {
				if err := d.Mailer.SendEmailVerification(toAddr, username, tok); err != nil {
					log.Printf("[resend_verification] failed to send email to %s: %v", toAddr, err)
				}
			}(email, claims.Sub, newToken)
		}

		writeJSON(w, http.StatusOK, map[string]string{"message": "Verification email sent."})
	}
}
