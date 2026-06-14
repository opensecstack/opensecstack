package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func ArchivePost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		id := r.PathValue("id")

		var authorUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1`, id).Scan(&authorUsername)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if authorUsername != claims.Sub {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		_, err = d.Pool.Exec(r.Context(),
			`UPDATE posts SET state = 'archived', updated_at = now() WHERE id = $1`, id)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func UnarchivePost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		id := r.PathValue("id")

		var authorUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1 AND p.state = 'archived'`, id).Scan(&authorUsername)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if authorUsername != claims.Sub {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		_, err = d.Pool.Exec(r.Context(),
			`UPDATE posts SET state = 'draft', updated_at = now() WHERE id = $1`, id)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
