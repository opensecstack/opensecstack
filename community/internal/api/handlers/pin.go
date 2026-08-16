package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

// PinPost pins a post to the top of the feed (admin only).
// POST /api/v1/posts/{id}/pin
func PinPost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}
		id := r.PathValue("id")

		// Unpin any currently pinned post first (only one pinned post at a time).
		_, _ = d.Pool.Exec(r.Context(), `UPDATE posts SET pinned=false WHERE pinned=true`)

		ct, err := d.Pool.Exec(r.Context(), `UPDATE posts SET pinned=true WHERE id=$1`, id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if ct.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found"})
			return
		}

		claims := middleware.ClaimsFrom(r.Context())
		var actorID string
		_ = d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&actorID)
		recordAudit(r.Context(), d.Pool, actorID, "pin_post", "post", id, "")
		w.WriteHeader(http.StatusNoContent)
	}
}

// UnpinPost removes the pin from a post (admin only).
// DELETE /api/v1/posts/{id}/pin
func UnpinPost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}
		id := r.PathValue("id")

		_, _ = d.Pool.Exec(r.Context(), `UPDATE posts SET pinned=false WHERE id=$1`, id)
		w.WriteHeader(http.StatusNoContent)
	}
}
