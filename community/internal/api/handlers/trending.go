package handlers

import (
	"net/http"
)

func ListTrendingFeed(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)

		rows, err := d.Pool.Query(r.Context(), `
			SELECT
				p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
				p.title, p.slug, p.cover_image_url, p.state,
				p.published_at::text, p.created_at::text, p.updated_at::text,
				p.scheduled_at::text, p.edited_at::text,
				COALESCE(
					array_agg(DISTINCT t.name) FILTER (WHERE t.name IS NOT NULL),
					'{}'
				) AS tags,
				(SELECT COUNT(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
				(SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
				p.views, p.locked, p.pinned, p.sensitive,
				(
					(SELECT COUNT(*) FROM reactions r WHERE r.post_id = p.id) * 3 + p.views
				)::float /
				POWER(EXTRACT(EPOCH FROM (now() - p.published_at)) / 3600 + 2, 1.5) AS score
			FROM posts p
			JOIN users u ON u.id = p.author_id
			LEFT JOIN post_tags pt ON pt.post_id = p.id
			LEFT JOIN tags t ON t.id = pt.tag_id
			WHERE p.state = 'published'
			  AND p.published_at > now() - INTERVAL '30 days'
			GROUP BY p.id, u.id
			ORDER BY score DESC
			LIMIT $1 OFFSET $2`,
			limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		type trendingPost struct {
			postRow
			Score float64 `json:"score"`
		}

		posts := []trendingPost{}
		for rows.Next() {
			var p trendingPost
			var tags []string
			scanArgs := append(scanPost(&p.postRow, &tags), &p.Score)
			if err := rows.Scan(scanArgs...); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			p.Tags = tags
			posts = append(posts, p)
		}

		writeJSON(w, http.StatusOK, map[string]any{"posts": posts, "count": len(posts)})
	}
}
