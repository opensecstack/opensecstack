package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/api/middleware"
)

// tokenHash returns the SHA-256 hex digest of a raw JWT string.
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// rawTokenFromRequest extracts the raw Bearer token string without verifying it.
func rawTokenFromRequest(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(header, "Bearer ")
}

// UpdateLastSeen updates the last_seen_at timestamp for a session identified by
// its token hash. Intended to be called in a goroutine from auth middleware.
func UpdateLastSeen(pool *pgxpool.Pool, hash string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = pool.Exec(ctx, `UPDATE user_sessions SET last_seen_at = NOW() WHERE token_hash = $1`, hash)
}

// SessionExists returns true when there is a non-expired session row for the
// given token hash. Used by the auth middleware to enforce revocation.
func SessionExists(ctx context.Context, pool *pgxpool.Pool, hash string) bool {
	var exists bool
	_ = pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_sessions WHERE token_hash = $1 AND expires_at > NOW())`,
		hash,
	).Scan(&exists)
	return exists
}

type sessionRow struct {
	ID         string    `json:"id"`
	DeviceInfo string    `json:"device_info"`
	IPAddress  string    `json:"ip_address"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	IsCurrent  bool      `json:"is_current"`
}

// ListSessions returns all active sessions for the authenticated user.
// GET /api/v1/me/sessions
func ListSessions(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		// Resolve user ID from username.
		var userID string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, claims.Sub,
		).Scan(&userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}

		currentHash := tokenHash(rawTokenFromRequest(r))

		rows, err := d.Pool.Query(r.Context(),
			`SELECT id, device_info, ip_address, created_at, last_seen_at
			 FROM user_sessions
			 WHERE user_id = $1 AND expires_at > NOW()
			 ORDER BY last_seen_at DESC`,
			userID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}
		defer rows.Close()

		sessions := []sessionRow{}
		for rows.Next() {
			var s sessionRow
			var dbID string
			if err := rows.Scan(&dbID, &s.DeviceInfo, &s.IPAddress, &s.CreatedAt, &s.LastSeenAt); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "scan error"})
				return
			}
			s.ID = dbID

			// To check is_current we need the token_hash of the stored row.
			// We query it separately to avoid exposing it in the list.
			var storedHash string
			_ = d.Pool.QueryRow(r.Context(),
				`SELECT token_hash FROM user_sessions WHERE id = $1`, dbID,
			).Scan(&storedHash)
			s.IsCurrent = storedHash == currentHash

			sessions = append(sessions, s)
		}
		if err := rows.Err(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}

		writeJSON(w, http.StatusOK, sessions)
	}
}

// RevokeSession deletes a specific session by ID.
// DELETE /api/v1/me/sessions/{id}
func RevokeSession(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		sessionID := r.PathValue("id")
		if sessionID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session id required"})
			return
		}

		// Resolve user ID.
		var userID string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, claims.Sub,
		).Scan(&userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}

		// Prevent revoking the current session.
		currentHash := tokenHash(rawTokenFromRequest(r))
		var storedHash string
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT token_hash FROM user_sessions WHERE id = $1 AND user_id = $2`,
			sessionID, userID,
		).Scan(&storedHash)
		if storedHash == currentHash {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot revoke current session"})
			return
		}

		tag, err := d.Pool.Exec(r.Context(),
			`DELETE FROM user_sessions WHERE id = $1 AND user_id = $2`,
			sessionID, userID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// RevokeAllSessions deletes all sessions for the authenticated user except the current one.
// DELETE /api/v1/me/sessions
func RevokeAllSessions(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		// Resolve user ID.
		var userID string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, claims.Sub,
		).Scan(&userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}

		// Find the current session ID so we can keep it. If the caller's
		// bearer token has no matching session row (e.g. it was already
		// revoked/expired elsewhere while the JWT itself is still valid),
		// currentSessionID stays empty and every session for this user is
		// deleted — an empty string must never be bound as the UUID
		// exclusion param below, or Postgres rejects it as invalid input.
		currentHash := tokenHash(rawTokenFromRequest(r))
		var currentSessionID string
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT id FROM user_sessions WHERE token_hash = $1`,
			currentHash,
		).Scan(&currentSessionID)

		if currentSessionID == "" {
			_, err = d.Pool.Exec(r.Context(),
				`DELETE FROM user_sessions WHERE user_id = $1`,
				userID,
			)
		} else {
			_, err = d.Pool.Exec(r.Context(),
				`DELETE FROM user_sessions WHERE user_id = $1 AND id != $2`,
				userID, currentSessionID,
			)
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
