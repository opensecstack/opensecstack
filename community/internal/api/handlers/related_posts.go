package handlers

import (
	"net/http"
)

type relatedPostAuthor struct {
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
}

type relatedPostRow struct {
	ID            string            `json:"id"`
	Title         string            `json:"title"`
	Slug          string            `json:"slug"`
	CoverImageURL *string           `json:"cover_image_url"`
	CreatedAt     string            `json:"created_at"`
	Author        relatedPostAuthor `json:"author"`
}

type relatedPostsResponse struct {
	Posts []relatedPostRow `json:"posts"`
}

func GetRelatedPosts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		postID := r.PathValue("id")

		rows, err := d.Pool.Query(r.Context(), `
			SELECT p.id, p.title, p.slug, p.cover_image_url, p.created_at::text,
			       u.username, u.display_name, u.avatar_url,
			       COUNT(pt2.tag_id) AS shared_tags
			FROM post_tags pt1
			JOIN post_tags pt2 ON pt2.tag_id = pt1.tag_id AND pt2.post_id != pt1.post_id
			JOIN posts p ON p.id = pt2.post_id AND p.state = 'published'
			JOIN users u ON u.id = p.author_id
			WHERE pt1.post_id = $1
			GROUP BY p.id, p.title, p.slug, p.cover_image_url, p.created_at,
			         u.username, u.display_name, u.avatar_url
			ORDER BY shared_tags DESC, p.created_at DESC
			LIMIT 4
		`, postID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		posts := []relatedPostRow{}
		for rows.Next() {
			var p relatedPostRow
			var sharedTags int64
			if err := rows.Scan(
				&p.ID, &p.Title, &p.Slug, &p.CoverImageURL, &p.CreatedAt,
				&p.Author.Username, &p.Author.DisplayName, &p.Author.AvatarURL,
				&sharedTags,
			); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			posts = append(posts, p)
		}

		writeJSON(w, http.StatusOK, relatedPostsResponse{Posts: posts})
	}
}
