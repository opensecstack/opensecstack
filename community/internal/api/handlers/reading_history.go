package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

// RecordRead upserts a post_reads row for the authenticated user.
// Route: POST /api/v1/posts/{id}/read
func RecordRead(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		postID := r.PathValue("id")

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, err := d.Pool.Exec(r.Context(),
			`INSERT INTO post_reads (user_id, post_id) VALUES ($1,$2)
			 ON CONFLICT (user_id, post_id) DO UPDATE SET read_at = now()`,
			userID, postID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListReadingHistory returns the authenticated user's reading history, newest first.
// Route: GET /api/v1/me/history
func ListReadingHistory(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		page := queryInt(r, "page", 1)
		limit := queryInt(r, "limit", 20)
		if limit > 50 {
			limit = 50
		}
		if page < 1 {
			page = 1
		}
		offset := (page - 1) * limit

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		rows, err := d.Pool.Query(r.Context(), `
SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
       p.title, p.slug, p.cover_image_url, p.state,
       p.published_at::text, p.created_at::text, p.updated_at::text,
       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
       (SELECT count(*) FROM reactions rx WHERE rx.post_id = p.id) AS reaction_count,
       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
       p.views,
       pr.read_at::text
FROM post_reads pr
JOIN posts p ON p.id = pr.post_id
JOIN users u ON u.id = p.author_id
LEFT JOIN post_tags pt ON pt.post_id = p.id
LEFT JOIN tags t ON t.id = pt.tag_id
WHERE pr.user_id = $1 AND p.state = 'published'
GROUP BY p.id, u.id, pr.read_at
ORDER BY pr.read_at DESC
LIMIT $2 OFFSET $3`,
			userID, limit, offset,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		type historyRow struct {
			postRow
			ReadAt string `json:"read_at"`
		}

		type historyResponse struct {
			Posts []historyRow `json:"posts"`
			Count int          `json:"count"`
		}

		posts := []historyRow{}
		for rows.Next() {
			var h historyRow
			var tags []string
			if err := rows.Scan(
				&h.ID, &h.AuthorID, &h.AuthorUsername, &h.AuthorName, &h.AuthorAvatar, &h.AuthorBadge,
				&h.Title, &h.Slug, &h.CoverImage, &h.State, &h.PublishedAt, &h.CreatedAt, &h.UpdatedAt,
				&tags, &h.ReactionCount, &h.CommentCount, &h.Views,
				&h.ReadAt,
			); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			h.Tags = tags
			posts = append(posts, h)
		}
		writeJSON(w, http.StatusOK, historyResponse{Posts: posts, Count: len(posts)})
	}
}
