package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
)

func LockPost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id := r.PathValue("id")

		var authorUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1`, id,
		).Scan(&authorUsername)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found"})
			return
		}
		if claims.Sub != authorUsername && !auth.HasRole(claims.Role, "moderator") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		_, err = d.Pool.Exec(r.Context(), `UPDATE posts SET locked=true WHERE id=$1`, id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		var actorID string
		d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&actorID)
		recordAudit(r.Context(), d.Pool, actorID, "lock_post", "post", id, "")
		w.WriteHeader(http.StatusNoContent)
	}
}

func UnlockPost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id := r.PathValue("id")

		var authorUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1`, id,
		).Scan(&authorUsername)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found"})
			return
		}
		if claims.Sub != authorUsername && !auth.HasRole(claims.Role, "moderator") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		_, err = d.Pool.Exec(r.Context(), `UPDATE posts SET locked=false WHERE id=$1`, id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		var actorID string
		d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&actorID)
		recordAudit(r.Context(), d.Pool, actorID, "unlock_post", "post", id, "")
		w.WriteHeader(http.StatusNoContent)
	}
}
