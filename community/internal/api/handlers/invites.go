package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func GenerateInvite(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "moderator") {
			return
		}

		claims := middleware.ClaimsFrom(r.Context())

		// Get caller's user ID
		var callerID string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`,
			claims.Sub,
		).Scan(&callerID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not resolve caller user"})
			return
		}

		var id, code, expiresAt, createdAt string
		err = d.Pool.QueryRow(r.Context(),
			`INSERT INTO invites (created_by) VALUES ($1) RETURNING id, code, expires_at::text, created_at::text`,
			callerID,
		).Scan(&id, &code, &expiresAt, &createdAt)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create invite"})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         id,
			"code":       code,
			"expires_at": expiresAt,
			"created_at": createdAt,
		})
	}
}

func ListInvites(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "moderator") {
			return
		}

		rows, err := d.Pool.Query(r.Context(), `
			SELECT i.id, i.code,
			       cu.username AS created_by_username,
			       uu.username AS used_by_username,
			       i.used_at::text, i.expires_at::text, i.created_at::text
			FROM invites i
			JOIN users cu ON cu.id = i.created_by
			LEFT JOIN users uu ON uu.id = i.used_by
			ORDER BY i.created_at DESC
			LIMIT 100
		`)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list invites"})
			return
		}
		defer rows.Close()

		type inviteRow struct {
			ID                string  `json:"id"`
			Code              string  `json:"code"`
			CreatedByUsername string  `json:"created_by_username"`
			UsedByUsername    *string `json:"used_by_username"`
			UsedAt            *string `json:"used_at"`
			ExpiresAt         string  `json:"expires_at"`
			CreatedAt         string  `json:"created_at"`
		}

		invites := make([]inviteRow, 0)
		for rows.Next() {
			var inv inviteRow
			if err := rows.Scan(
				&inv.ID, &inv.Code,
				&inv.CreatedByUsername, &inv.UsedByUsername,
				&inv.UsedAt, &inv.ExpiresAt, &inv.CreatedAt,
			); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "scan error"})
				return
			}
			invites = append(invites, inv)
		}
		if err := rows.Err(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "row iteration error"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"invites": invites})
	}
}

func ValidateInvite(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.PathValue("code")
		if code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing code"})
			return
		}

		var used, expired bool
		err := d.Pool.QueryRow(r.Context(),
			`SELECT used_at IS NOT NULL, expires_at < now() FROM invites WHERE code=$1`,
			code,
		).Scan(&used, &expired)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason": "not found"})
			return
		}
		if used {
			writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason": "already used"})
			return
		}
		if expired {
			writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason": "expired"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"valid": true})
	}
}
