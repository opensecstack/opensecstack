package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func BookmarkPost(d Deps) http.HandlerFunc {
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
			`INSERT INTO bookmarks (user_id, post_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			userID, postID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func UnbookmarkPost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		postID := r.PathValue("id")

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM bookmarks WHERE user_id=$1 AND post_id=$2`,
			userID, postID,
		)
		w.WriteHeader(http.StatusNoContent)
	}
}

func ListMyBookmarks(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)

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
       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
       p.views
FROM bookmarks b
JOIN posts p ON p.id = b.post_id
JOIN users u ON u.id = p.author_id
LEFT JOIN post_tags pt ON pt.post_id = p.id
LEFT JOIN tags t ON t.id = pt.tag_id
WHERE b.user_id = $1 AND p.state = 'published'
GROUP BY p.id, u.id, b.created_at
ORDER BY b.created_at DESC
LIMIT $2 OFFSET $3`,
			userID, limit, offset,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		posts := []postRow{}
		for rows.Next() {
			var p postRow
			var tags []string
			if err := rows.Scan(
				&p.ID, &p.AuthorID, &p.AuthorUsername, &p.AuthorName, &p.AuthorAvatar, &p.AuthorBadge,
				&p.Title, &p.Slug, &p.CoverImage, &p.State, &p.PublishedAt, &p.CreatedAt, &p.UpdatedAt,
				&tags, &p.ReactionCount, &p.CommentCount, &p.Views,
			); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			p.Tags = tags
			posts = append(posts, p)
		}
		writeJSON(w, http.StatusOK, postListResponse{Posts: posts, Count: len(posts)})
	}
}

func GetBookmarkStatus(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		postID := r.PathValue("id")

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusOK, map[string]bool{"bookmarked": false})
			return
		}

		var exists bool
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM bookmarks WHERE user_id=$1 AND post_id=$2)`,
			userID, postID,
		).Scan(&exists)
		writeJSON(w, http.StatusOK, map[string]bool{"bookmarked": exists})
	}
}
