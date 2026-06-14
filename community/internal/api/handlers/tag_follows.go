package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func FollowTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		slug := r.PathValue("slug")

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		var tagID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM tags WHERE slug=$1`, slug).Scan(&tagID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "tag not found"})
			return
		}

		var exists bool
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tag_follows WHERE user_id=$1 AND tag_id=$2)`,
			userID, tagID,
		).Scan(&exists)
		if exists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "already following"})
			return
		}

		_, err := d.Pool.Exec(r.Context(),
			`INSERT INTO tag_follows (user_id, tag_id) VALUES ($1, $2)`,
			userID, tagID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func UnfollowTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		slug := r.PathValue("slug")

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		var tagID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM tags WHERE slug=$1`, slug).Scan(&tagID); err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM tag_follows WHERE user_id=$1 AND tag_id=$2`,
			userID, tagID,
		)
		w.WriteHeader(http.StatusNoContent)
	}
}

func GetTagFollowStatus(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		slug := r.PathValue("slug")

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusOK, map[string]bool{"following": false})
			return
		}

		var tagID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM tags WHERE slug=$1`, slug).Scan(&tagID); err != nil {
			writeJSON(w, http.StatusOK, map[string]bool{"following": false})
			return
		}

		var exists bool
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tag_follows WHERE user_id=$1 AND tag_id=$2)`,
			userID, tagID,
		).Scan(&exists)
		writeJSON(w, http.StatusOK, map[string]bool{"following": exists})
	}
}

func ListFollowingTagsFeed(d Deps) http.HandlerFunc {
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
			writeJSON(w, http.StatusOK, postListResponse{Posts: []postRow{}, Count: 0})
			return
		}

		rows, err := d.Pool.Query(r.Context(), `
			SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
			       p.title, p.slug, p.cover_image_url, p.state,
			       p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
			       p.edited_at::text,
			       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
			       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
			       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
			       p.views, p.locked, p.pinned, p.sensitive
			FROM posts p
			JOIN users u ON u.id = p.author_id
			JOIN tag_follows tf ON tf.user_id = $1
			JOIN post_tags pt ON pt.post_id = p.id AND pt.tag_id = tf.tag_id
			LEFT JOIN post_tags pt2 ON pt2.post_id = p.id
			LEFT JOIN tags t ON t.id = pt2.tag_id
			WHERE p.state = 'published'
			GROUP BY p.id, u.id
			ORDER BY p.published_at DESC
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
			if err := rows.Scan(scanPost(&p, &tags)...); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			p.Tags = tags
			posts = append(posts, p)
		}
		writeJSON(w, http.StatusOK, postListResponse{Posts: posts, Count: len(posts)})
	}
}
