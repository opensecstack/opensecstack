package handlers

// Wire: mux.HandleFunc("PUT /api/v1/me/password", handlers.ChangePassword(d))

import (
	"net/http"
	"strings"

	"github.com/opensecstack/community/internal/api/middleware"
)

// ChangePassword handles PUT /api/v1/me/password.
// Requires a valid JWT. Verifies the current password before updating.
func ChangePassword(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		// Validate new password length before touching the DB.
		if len(req.NewPassword) < 8 {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "new password must be at least 8 characters"})
			return
		}

		// Fetch current password hash.
		var storedHash string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT COALESCE(password_hash, '') FROM users WHERE username = $1`,
			claims.Sub,
		).Scan(&storedHash)
		if err != nil || storedHash == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not verify current password"})
			return
		}

		// Verify current password. Modern accounts (Register, and Login after its
		// lazy-migration) store a bcrypt hash; older accounts may still carry the
		// legacy sha256(pepper+password) hash. Accept either, matching Login's logic,
		// so this check is never stricter than the one that let the user log in.
		var currentOK bool
		if strings.HasPrefix(storedHash, "$2") {
			currentOK = bcryptVerify(req.CurrentPassword, storedHash)
		} else {
			currentOK = sha256Hash(d.Cfg.Pepper+":"+req.CurrentPassword) == storedHash
		}
		if !currentOK {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "current password is incorrect"})
			return
		}

		// Hash and store the new password using bcrypt (the modern scheme — never
		// write the new password back in the legacy sha256+pepper format).
		newHash, err := bcryptHash(req.NewPassword)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update password"})
			return
		}
		_, err = d.Pool.Exec(r.Context(),
			`UPDATE users SET password_hash = $1 WHERE username = $2`,
			newHash, claims.Sub,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update password"})
			return
		}

		// Notify the user that their password changed.
		var userID string
		if e := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); e == nil {
			createSystemNotification(r.Context(), d.Pool, userID, "password_changed", nil)
		}

		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}
