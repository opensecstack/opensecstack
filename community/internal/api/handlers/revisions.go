package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func ListPostRevisions(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		id := r.PathValue("id")

		// Verify ownership
		var authorUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1`, id).
			Scan(&authorUsername)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if authorUsername != claims.Sub {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		rows, err := d.Pool.Query(r.Context(),
			`SELECT id, title, body, revised_at::text
             FROM post_revisions
             WHERE post_id = $1
             ORDER BY revised_at DESC
             LIMIT 50`, id)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type revision struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			Body      string `json:"body"`
			RevisedAt string `json:"revised_at"`
		}

		revisions := []revision{}
		for rows.Next() {
			var rev revision
			if err := rows.Scan(&rev.ID, &rev.Title, &rev.Body, &rev.RevisedAt); err != nil {
				http.Error(w, "scan error", http.StatusInternalServerError)
				return
			}
			revisions = append(revisions, rev)
		}

		writeJSON(w, http.StatusOK, map[string]any{"revisions": revisions})
	}
}
