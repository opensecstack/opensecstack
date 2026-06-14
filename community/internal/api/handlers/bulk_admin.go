package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

// BulkSetRole handles POST /api/v1/admin/users/bulk-role.
// Body: {"usernames": ["alice", "bob"], "role": "moderator"}
func BulkSetRole(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		var req struct {
			Usernames []string `json:"usernames"`
			Role      string   `json:"role"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if len(req.Usernames) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "usernames must not be empty"})
			return
		}

		validRoles := map[string]bool{
			"viewer":    true,
			"author":    true,
			"moderator": true,
			"admin":     true,
		}
		if !validRoles[req.Role] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid role"})
			return
		}

		// Prevent the caller from demoting themselves via a bulk action.
		claims := middleware.ClaimsFrom(r.Context())
		filtered := make([]string, 0, len(req.Usernames))
		for _, u := range req.Usernames {
			if u != claims.Sub {
				filtered = append(filtered, u)
			}
		}

		tag, err := d.Pool.Exec(r.Context(),
			`UPDATE users SET role=$1, updated_at=now() WHERE username = ANY($2)`,
			req.Role, filtered,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"updated": tag.RowsAffected()})
	}
}

// BulkBanUsers handles POST /api/v1/admin/users/bulk-ban.
// Body: {"usernames": ["alice", "bob"], "banned": true}
func BulkBanUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		var req struct {
			Usernames []string `json:"usernames"`
			Banned    bool     `json:"banned"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if len(req.Usernames) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "usernames must not be empty"})
			return
		}

		// Prevent the caller from banning themselves via a bulk action.
		claims := middleware.ClaimsFrom(r.Context())
		filtered := make([]string, 0, len(req.Usernames))
		for _, u := range req.Usernames {
			if u != claims.Sub {
				filtered = append(filtered, u)
			}
		}

		tag, err := d.Pool.Exec(r.Context(),
			`UPDATE users SET banned=$1, updated_at=now() WHERE username = ANY($2)`,
			req.Banned, filtered,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"updated": tag.RowsAffected()})
	}
}
