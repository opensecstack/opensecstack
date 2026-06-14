package handlers

// Wire: mux.HandleFunc("POST /api/v1/auth/forgot-password", handlers.ForgotPassword(d))
// Wire: mux.HandleFunc("POST /api/v1/auth/reset-password", handlers.ResetPassword(d))

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// ForgotPassword handles POST /api/v1/auth/forgot-password.
// It accepts an email address and sends a password reset link if the user exists.
// Always returns 200 to avoid leaking whether an email is registered.
func ForgotPassword(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		const genericOK = "If that email is registered, a reset link has been sent."

		// Look up user by email.
		var userID, username string
		row := d.Pool.QueryRow(r.Context(),
			`SELECT id, COALESCE(NULLIF(display_name,''), username) FROM users WHERE email = $1`,
			req.Email,
		)
		if err := row.Scan(&userID, &username); err != nil {
			// User not found — return generic response to avoid enumeration.
			writeJSON(w, http.StatusOK, map[string]string{"message": genericOK})
			return
		}

		// Generate a cryptographically random 32-byte hex token.
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate token"})
			return
		}
		token := hex.EncodeToString(b)

		// Insert token into password_reset_tokens.
		_, err := d.Pool.Exec(r.Context(),
			`INSERT INTO password_reset_tokens (user_id, token, expires_at)
			 VALUES ($1, $2, now() + interval '1 hour')`,
			userID, token,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create reset token"})
			return
		}

		// Send the reset email (or log in dev mode).
		if d.Mailer != nil {
			if err := d.Mailer.SendPasswordReset(req.Email, token, username); err != nil {
				log.Printf("[password_reset] failed to send email to %s: %v", req.Email, err)
			}
		} else {
			log.Printf("[email] password reset token for %s: %s", req.Email, token)
		}

		writeJSON(w, http.StatusOK, map[string]string{"message": genericOK})
	}
}

// ResetPassword handles POST /api/v1/auth/reset-password.
// It validates the token and updates the user's password atomically inside a
// transaction with a FOR UPDATE lock so concurrent requests with the same token
// cannot both succeed (prevents token reuse).
func ResetPassword(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token    string `json:"token"`
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if len(req.Password) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
			return
		}

		// Hash the new password with bcrypt before opening the transaction so we
		// don't hold the DB lock during a potentially slow CPU operation.
		newHash, err := bcryptHash(req.Password)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash password"})
			return
		}

		ctx := r.Context()

		// Begin transaction.
		tx, err := d.Pool.Begin(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}
		// Ensure rollback on any early return; harmless if Commit already succeeded.
		defer func(t pgx.Tx, c context.Context) { _ = t.Rollback(c) }(tx, ctx)

		// Step 1: lock the token row to prevent concurrent reuse.
		var tokenID, userID string
		err = tx.QueryRow(ctx,
			`SELECT id, user_id FROM password_reset_tokens
			 WHERE token = $1 AND used = false AND expires_at > now()
			 FOR UPDATE`,
			req.Token,
		).Scan(&tokenID, &userID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired reset token"})
			return
		}

		// Step 2: update the user's password hash.
		if _, err = tx.Exec(ctx,
			`UPDATE users SET password_hash = $1 WHERE id = $2`,
			newHash, userID,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update password"})
			return
		}

		// Step 3: mark the token as used.
		if _, err = tx.Exec(ctx,
			`UPDATE password_reset_tokens SET used = true WHERE id = $1`,
			tokenID,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to invalidate token"})
			return
		}

		// Step 4: commit — all three changes land atomically.
		if err = tx.Commit(ctx); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "transaction commit failed"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"message": "Password updated successfully."})
	}
}
