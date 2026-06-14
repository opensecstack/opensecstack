package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func SuppressTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		slug := r.PathValue("slug")

		var tagID string
		err := d.Pool.QueryRow(r.Context(), `SELECT id FROM tags WHERE slug = $1`, slug).Scan(&tagID)
		if err != nil {
			http.Error(w, "tag not found", http.StatusNotFound)
			return
		}

		var userID string
		err = d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username = $1`, claims.Sub).Scan(&userID)
		if err != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		_, err = d.Pool.Exec(r.Context(),
			`INSERT INTO tag_suppressions (user_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			userID, tagID)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func UnsuppressTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		slug := r.PathValue("slug")

		_, err := d.Pool.Exec(r.Context(), `
            DELETE FROM tag_suppressions ts
            USING tags t, users u
            WHERE t.slug = $1 AND u.username = $2
              AND ts.tag_id = t.id AND ts.user_id = u.id`,
			slug, claims.Sub)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func GetTagSuppressionStatus(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		slug := r.PathValue("slug")

		var exists bool
		err := d.Pool.QueryRow(r.Context(), `
            SELECT EXISTS (
                SELECT 1 FROM tag_suppressions ts
                JOIN tags t ON t.id = ts.tag_id
                JOIN users u ON u.id = ts.user_id
                WHERE t.slug = $1 AND u.username = $2
            )`, slug, claims.Sub).Scan(&exists)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"suppressed": exists})
	}
}
