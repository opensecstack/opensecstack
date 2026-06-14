package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

type userProfile struct {
	ID              string  `json:"id"`
	Username        string  `json:"username"`
	DisplayName     string  `json:"display_name"`
	Bio             string  `json:"bio"`
	AvatarURL       *string `json:"avatar_url"`
	PlatformBadge   *string `json:"platform_badge"`
	Role            string  `json:"role"`
	CreatedAt       string  `json:"created_at"`
	Website         string  `json:"website"`
	GithubUsername  string  `json:"github_username"`
	TwitterUsername string  `json:"twitter_username"`
	Location        string  `json:"location"`
	Certifications  string  `json:"certifications"`
	Specialization  string  `json:"specialization"`
}

func GetUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		var u userProfile
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id, username, display_name, bio, avatar_url, platform_badge, role, created_at::text,
			        website, github_username, twitter_username, location, certifications, specialization
			 FROM users WHERE username=$1`, username,
		).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Bio, &u.AvatarURL, &u.PlatformBadge, &u.Role, &u.CreatedAt,
			&u.Website, &u.GithubUsername, &u.TwitterUsername, &u.Location, &u.Certifications, &u.Specialization)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusOK, u)
	}
}

// GetUserPinnedPost returns the single pinned published post for a given user,
// or {"post": null} when none is pinned.
// GET /api/v1/users/{username}/pinned-post
func GetUserPinnedPost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")

		var p postRow
		var tags []string
		err := d.Pool.QueryRow(r.Context(), `
			SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
			       p.title, p.slug, p.cover_image_url, p.state,
			       p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
			       p.edited_at::text,
			       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
			       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
			       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
			       p.views, p.locked, p.pinned, p.sensitive
			FROM posts p
			JOIN users u ON u.id = p.author_id AND u.username = $1
			LEFT JOIN post_tags pt ON pt.post_id = p.id
			LEFT JOIN tags t ON t.id = pt.tag_id
			WHERE p.state = 'published' AND p.pinned = true
			GROUP BY p.id, u.id
			LIMIT 1`, username,
		).Scan(scanPost(&p, &tags)...)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"post": nil})
			return
		}
		p.Tags = tags
		writeJSON(w, http.StatusOK, map[string]any{"post": p})
	}
}

func ListUserPosts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)

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
			JOIN users u ON u.id = p.author_id AND u.username = $1
			LEFT JOIN post_tags pt ON pt.post_id = p.id
			LEFT JOIN tags t ON t.id = pt.tag_id
			WHERE p.state = 'published'
			GROUP BY p.id, u.id
			ORDER BY p.published_at DESC
			LIMIT $2 OFFSET $3`, username, limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var posts []postRow
		for rows.Next() {
			var p postRow
			var tags []string
			if err := rows.Scan(scanPost(&p, &tags)...); err != nil {
				continue
			}
			p.Tags = tags
			posts = append(posts, p)
		}
		if posts == nil {
			posts = []postRow{}
		}
		writeJSON(w, http.StatusOK, postListResponse{Posts: posts, Count: len(posts)})
	}
}

func GetMyPosts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		limit := queryInt(r, "limit", 50)
		offset := queryInt(r, "offset", 0)

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
			JOIN users u ON u.id = p.author_id AND u.username = $1
			LEFT JOIN post_tags pt ON pt.post_id = p.id
			LEFT JOIN tags t ON t.id = pt.tag_id
			GROUP BY p.id, u.id
			ORDER BY p.updated_at DESC
			LIMIT $2 OFFSET $3`, claims.Sub, limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var posts []postRow
		for rows.Next() {
			var p postRow
			var tags []string
			if err := rows.Scan(scanPost(&p, &tags)...); err != nil {
				continue
			}
			p.Tags = tags
			posts = append(posts, p)
		}
		if posts == nil {
			posts = []postRow{}
		}
		writeJSON(w, http.StatusOK, postListResponse{Posts: posts, Count: len(posts)})
	}
}

func SearchUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if len(q) < 1 {
			writeJSON(w, http.StatusOK, map[string]any{"users": []any{}})
			return
		}
		rows, err := d.Pool.Query(r.Context(),
			`SELECT username, display_name, avatar_url FROM users WHERE username ILIKE $1 LIMIT 8`,
			q+"%",
		)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"users": []any{}})
			return
		}
		defer rows.Close()
		type userHit struct {
			Username    string  `json:"username"`
			DisplayName string  `json:"display_name"`
			AvatarURL   *string `json:"avatar_url"`
		}
		var users []userHit
		for rows.Next() {
			var u userHit
			if err := rows.Scan(&u.Username, &u.DisplayName, &u.AvatarURL); err != nil {
				continue
			}
			users = append(users, u)
		}
		if users == nil {
			users = []userHit{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})
	}
}

func UpdateMe(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var req struct {
			DisplayName     string  `json:"display_name"`
			Bio             string  `json:"bio"`
			AvatarURL       *string `json:"avatar_url"`
			PlatformBadge   *string `json:"platform_badge"`
			Website         string  `json:"website"`
			GithubUsername  string  `json:"github_username"`
			TwitterUsername string  `json:"twitter_username"`
			Location        string  `json:"location"`
			Certifications  string  `json:"certifications"`
			Specialization  string  `json:"specialization"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		_, err := d.Pool.Exec(r.Context(),
			`UPDATE users SET display_name=$1, bio=$2, avatar_url=$3, platform_badge=$4,
			                  website=$5, github_username=$6, twitter_username=$7,
			                  location=$8, certifications=$9, specialization=$10, updated_at=now()
			 WHERE username=$11`,
			req.DisplayName, req.Bio, req.AvatarURL, req.PlatformBadge,
			req.Website, req.GithubUsername, req.TwitterUsername,
			req.Location, req.Certifications, req.Specialization, claims.Sub,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
