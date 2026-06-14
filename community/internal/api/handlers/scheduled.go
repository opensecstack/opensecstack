package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

type scheduledPostRow struct {
	ID            string  `json:"id"`
	Title         string  `json:"title"`
	Slug          string  `json:"slug"`
	CoverImageURL *string `json:"cover_image_url"`
	ScheduledAt   string  `json:"scheduled_at"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type scheduledPostsResponse struct {
	Posts []scheduledPostRow `json:"posts"`
	Total int                `json:"total"`
}

func GetScheduledPosts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var authorID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, claims.Sub,
		).Scan(&authorID); err != nil {
			writeJSON(w, http.StatusOK, scheduledPostsResponse{Posts: []scheduledPostRow{}, Total: 0})
			return
		}

		rows, err := d.Pool.Query(r.Context(), `
			SELECT id, title, slug, cover_image_url, scheduled_at::text, created_at::text, updated_at::text
			FROM posts
			WHERE author_id = $1 AND state = 'scheduled'
			ORDER BY scheduled_at ASC`, authorID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var posts []scheduledPostRow
		for rows.Next() {
			var p scheduledPostRow
			if err := rows.Scan(
				&p.ID, &p.Title, &p.Slug, &p.CoverImageURL,
				&p.ScheduledAt, &p.CreatedAt, &p.UpdatedAt,
			); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			posts = append(posts, p)
		}
		if posts == nil {
			posts = []scheduledPostRow{}
		}
		writeJSON(w, http.StatusOK, scheduledPostsResponse{Posts: posts, Total: len(posts)})
	}
}
