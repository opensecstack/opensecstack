package handlers

import (
	"net/http"
	"time"

	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
)

func SchedulePost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id := r.PathValue("id")

		var req struct {
			ScheduledAt string `json:"scheduled_at"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		t, err := time.Parse(time.RFC3339, req.ScheduledAt)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid scheduled_at, use RFC3339"})
			return
		}
		if !t.After(time.Now()) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scheduled_at must be in the future"})
			return
		}

		var authorUsername string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id=$1`, id,
		).Scan(&authorUsername); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found"})
			return
		}
		if claims.Sub != authorUsername && !auth.HasRole(claims.Role, "moderator") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		if _, err := d.Pool.Exec(r.Context(),
			`UPDATE posts SET state='scheduled', scheduled_at=$1, updated_at=now() WHERE id=$2`,
			t, id,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func UnschedulePost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id := r.PathValue("id")

		var authorUsername string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id=$1`, id,
		).Scan(&authorUsername); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found"})
			return
		}
		if claims.Sub != authorUsername && !auth.HasRole(claims.Role, "moderator") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`UPDATE posts SET state='draft', scheduled_at=NULL, updated_at=now() WHERE id=$1`, id)
		w.WriteHeader(http.StatusNoContent)
	}
}
