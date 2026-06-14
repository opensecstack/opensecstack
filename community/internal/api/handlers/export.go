package handlers

// Wire in server.go:
//   mux.Handle("GET /api/v1/me/export", auth(http.HandlerFunc(handlers.ExportMyData(d))))

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/opensecstack/community/internal/api/middleware"
)

type exportProfile struct {
	ID          string  `json:"id"`
	Username    string  `json:"username"`
	Email       string  `json:"email"`
	DisplayName string  `json:"display_name"`
	Bio         string  `json:"bio"`
	AvatarURL   *string `json:"avatar_url"`
	CreatedAt   string  `json:"created_at"`
	Role        string  `json:"role"`
}

type exportPost struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Body        *string  `json:"body"`
	Status      string   `json:"status"`
	CreatedAt   string   `json:"created_at"`
	PublishedAt *string  `json:"published_at"`
	Tags        []string `json:"tags"`
}

type exportComment struct {
	ID        string `json:"id"`
	PostID    string `json:"post_id"`
	Body      string `json:"body"`
	CreatedAt string `json:"created_at"`
}

type exportPayload struct {
	ExportedAt string          `json:"exported_at"`
	Profile    exportProfile   `json:"profile"`
	Posts      []exportPost    `json:"posts"`
	Comments   []exportComment `json:"comments"`
	Following  []string        `json:"following"`
	Followers  []string        `json:"followers"`
	Bookmarks  []string        `json:"bookmarks"`
}

// ExportMyData handles GET /api/v1/me/export.
// It collects all data belonging to the authenticated user and returns it as a
// downloadable JSON file (Content-Disposition: attachment).
func ExportMyData(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		ctx := r.Context()

		// 1. Resolve user ID and profile.
		var profile exportProfile
		err := d.Pool.QueryRow(ctx,
			`SELECT id, username, email, display_name, bio, avatar_url, created_at::text, role
			 FROM users WHERE username=$1`, claims.Sub,
		).Scan(
			&profile.ID, &profile.Username, &profile.Email,
			&profile.DisplayName, &profile.Bio, &profile.AvatarURL,
			&profile.CreatedAt, &profile.Role,
		)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		userID := profile.ID

		// 2. Posts.
		postRows, err := d.Pool.Query(ctx, `
			SELECT p.id, p.title, p.body, p.state, p.created_at::text, p.published_at::text,
			       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags
			FROM posts p
			LEFT JOIN post_tags pt ON pt.post_id = p.id
			LEFT JOIN tags t ON t.id = pt.tag_id
			WHERE p.author_id = $1
			GROUP BY p.id
			ORDER BY p.created_at DESC`, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer postRows.Close()

		posts := []exportPost{}
		for postRows.Next() {
			var p exportPost
			var tags []string
			if err := postRows.Scan(&p.ID, &p.Title, &p.Body, &p.Status, &p.CreatedAt, &p.PublishedAt, &tags); err != nil {
				continue
			}
			p.Tags = tags
			posts = append(posts, p)
		}
		postRows.Close()

		// 3. Comments.
		commentRows, err := d.Pool.Query(ctx, `
			SELECT id, post_id, body, created_at::text
			FROM comments
			WHERE author_id = $1
			ORDER BY created_at DESC`, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer commentRows.Close()

		comments := []exportComment{}
		for commentRows.Next() {
			var c exportComment
			if err := commentRows.Scan(&c.ID, &c.PostID, &c.Body, &c.CreatedAt); err != nil {
				continue
			}
			comments = append(comments, c)
		}
		commentRows.Close()

		// 4. Following (usernames this user follows).
		followingRows, err := d.Pool.Query(ctx, `
			SELECT u.username
			FROM follows f
			JOIN users u ON u.id = f.following_id
			WHERE f.follower_id = $1
			ORDER BY f.created_at DESC`, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer followingRows.Close()

		following := []string{}
		for followingRows.Next() {
			var username string
			if err := followingRows.Scan(&username); err != nil {
				continue
			}
			following = append(following, username)
		}
		followingRows.Close()

		// 5. Followers (usernames that follow this user).
		followerRows, err := d.Pool.Query(ctx, `
			SELECT u.username
			FROM follows f
			JOIN users u ON u.id = f.follower_id
			WHERE f.following_id = $1
			ORDER BY f.created_at DESC`, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer followerRows.Close()

		followers := []string{}
		for followerRows.Next() {
			var username string
			if err := followerRows.Scan(&username); err != nil {
				continue
			}
			followers = append(followers, username)
		}
		followerRows.Close()

		// 6. Bookmarks (slugs of bookmarked posts).
		bookmarkRows, err := d.Pool.Query(ctx, `
			SELECT p.slug
			FROM bookmarks b
			JOIN posts p ON p.id = b.post_id
			WHERE b.user_id = $1
			ORDER BY b.created_at DESC`, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer bookmarkRows.Close()

		bookmarks := []string{}
		for bookmarkRows.Next() {
			var slug string
			if err := bookmarkRows.Scan(&slug); err != nil {
				continue
			}
			bookmarks = append(bookmarks, slug)
		}
		bookmarkRows.Close()

		payload := exportPayload{
			ExportedAt: time.Now().UTC().Format(time.RFC3339),
			Profile:    profile,
			Posts:      posts,
			Comments:   comments,
			Following:  following,
			Followers:  followers,
			Bookmarks:  bookmarks,
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="my-data.json"`)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(payload)
	}
}
