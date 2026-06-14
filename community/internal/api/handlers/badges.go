package handlers

import (
	"net/http"
)

var allowedBadges = map[string]bool{
	"Staff":           true,
	"Moderator":       true,
	"Top Contributor": true,
	"Verified":        true,
	"Alumni":          true,
}

// SetUserBadge handles PUT /api/v1/admin/users/{username}/badge.
func SetUserBadge(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		targetUsername := r.PathValue("username")

		var req struct {
			Badge string `json:"badge"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if !allowedBadges[req.Badge] {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "unknown badge value"})
			return
		}

		tag, err := d.Pool.Exec(r.Context(),
			`UPDATE users SET platform_badge = $1, updated_at = now() WHERE username = $2`,
			req.Badge, targetUsername,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// RemoveUserBadge handles DELETE /api/v1/admin/users/{username}/badge.
func RemoveUserBadge(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		targetUsername := r.PathValue("username")

		tag, err := d.Pool.Exec(r.Context(),
			`UPDATE users SET platform_badge = NULL, updated_at = now() WHERE username = $1`,
			targetUsername,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}
