package handlers

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/db"
	"github.com/opensecstack/community/internal/search"
)

type postRow struct {
	ID                 string   `json:"id"`
	AuthorID           string   `json:"author_id"`
	AuthorUsername     string   `json:"author_username"`
	AuthorName         string   `json:"author_display_name"`
	AuthorAvatar       *string  `json:"author_avatar_url"`
	AuthorBadge        *string  `json:"author_platform_badge"`
	Title              string   `json:"title"`
	Slug               string   `json:"slug"`
	Body               *string  `json:"body,omitempty"`
	CoverImage         *string  `json:"cover_image_url"`
	State              string   `json:"state"`
	PublishedAt        *string  `json:"published_at"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
	ScheduledAt        *string  `json:"scheduled_at,omitempty"`
	EditedAt           *string  `json:"edited_at,omitempty"`
	Tags               []string `json:"tags"`
	ReactionCount      int64    `json:"reaction_count"`
	CommentCount       int64    `json:"comment_count"`
	Views              int64    `json:"views"`
	Locked             bool     `json:"locked"`
	Pinned             bool     `json:"pinned"`
	CanonicalURL       *string  `json:"canonical_url"`
	ReadingTimeMinutes int      `json:"reading_time_minutes,omitempty"`
	Sensitive          bool     `json:"sensitive"`
}

// readingTime returns the estimated reading time in minutes (minimum 1).
func readingTime(body string) int {
	words := len(strings.Fields(body))
	mins := words / 200
	if mins < 1 {
		return 1
	}
	return mins
}

type postListResponse struct {
	Posts []postRow `json:"posts"`
	Count int       `json:"count"`
}

func scanPost(p *postRow, tags *[]string) []any {
	return []any{
		&p.ID, &p.AuthorID, &p.AuthorUsername, &p.AuthorName, &p.AuthorAvatar, &p.AuthorBadge,
		&p.Title, &p.Slug, &p.CoverImage, &p.State, &p.PublishedAt, &p.CreatedAt, &p.UpdatedAt, &p.ScheduledAt,
		&p.EditedAt, tags, &p.ReactionCount, &p.CommentCount, &p.Views, &p.Locked, &p.Pinned, &p.Sensitive,
	}
}

func scanPostWithBody(p *postRow, tags *[]string) []any {
	return []any{
		&p.ID, &p.AuthorID, &p.AuthorUsername, &p.AuthorName, &p.AuthorAvatar, &p.AuthorBadge,
		&p.Title, &p.Slug, &p.Body, &p.CoverImage, &p.State, &p.PublishedAt, &p.CreatedAt, &p.UpdatedAt, &p.ScheduledAt,
		&p.EditedAt, tags, &p.ReactionCount, &p.CommentCount, &p.Views, &p.Locked, &p.Pinned, &p.CanonicalURL, &p.Sensitive,
	}
}

func ListPosts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)
		sort := r.URL.Query().Get("sort")

		// resolve optional caller for block and suppression filtering
		var blockerID any
		var suppressorID any
		if claims := middleware.ClaimsFrom(r.Context()); claims != nil {
			var uid string
			if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&uid); err == nil {
				blockerID = uid
				suppressorID = uid
			}
		}

		rows, err := d.Pool.Query(r.Context(), db.SortedListPostsQueryWithBlocksAndSuppressions(sort), limit, offset, blockerID, suppressorID)
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
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
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

func ListFeed(d Deps) http.HandlerFunc {
	return ListPosts(d)
}

func GetPost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		row := d.Pool.QueryRow(r.Context(), db.QueryGetPostBySlug, slug)

		var p postRow
		var tags []string
		if err := row.Scan(scanPostWithBody(&p, &tags)...); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found"})
			return
		}
		p.Tags = tags
		if p.Body != nil {
			p.ReadingTimeMinutes = readingTime(*p.Body)
		}
		writeJSON(w, http.StatusOK, p)
	}
}

func CreatePost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var req struct {
			Title        string   `json:"title"`
			Body         string   `json:"body"`
			CoverImage   string   `json:"cover_image_url"`
			Tags         []string `json:"tags"`
			CanonicalURL *string  `json:"canonical_url"`
			Sensitive    bool     `json:"sensitive"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if strings.TrimSpace(req.Title) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "title is required"})
			return
		}

		slug := slugify(req.Title) + "-" + uuid.New().String()[:8]

		var authorID string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, claims.Sub,
		).Scan(&authorID)
		if err != nil {
			err = d.Pool.QueryRow(r.Context(),
				`INSERT INTO users (username, display_name, role) VALUES ($1,$1,$2) RETURNING id`,
				claims.Sub, claims.Role,
			).Scan(&authorID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		}

		var id string
		err = d.Pool.QueryRow(r.Context(),
			`INSERT INTO posts (author_id, title, slug, body, cover_image_url, canonical_url, sensitive)
			 VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7)
			 RETURNING id`,
			authorID, req.Title, slug, req.Body, req.CoverImage, req.CanonicalURL, req.Sensitive,
		).Scan(&id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		if err := upsertTags(r.Context(), d, id, req.Tags); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{"id": id, "slug": slug})
	}
}

func UpdatePost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id := r.PathValue("id")

		var req struct {
			Title        string   `json:"title"`
			Body         string   `json:"body"`
			CoverImage   string   `json:"cover_image_url"`
			Tags         []string `json:"tags"`
			CanonicalURL *string  `json:"canonical_url"`
			Sensitive    bool     `json:"sensitive"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		var authorUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1`, id,
		).Scan(&authorUsername)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found"})
			return
		}
		if authorUsername != claims.Sub && !auth.HasRole(claims.Role, "moderator") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		// snapshot current version before overwriting
		_, err = d.Pool.Exec(r.Context(),
			`INSERT INTO post_revisions (post_id, title, body)
             SELECT id, title, body FROM posts WHERE id = $1`, id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		_, err = d.Pool.Exec(r.Context(),
			`UPDATE posts SET title=$1, body=$2, cover_image_url=NULLIF($3,''), canonical_url=$5, sensitive=$6, updated_at=now(),
			 edited_at = CASE WHEN state = 'published' THEN now() ELSE edited_at END
			 WHERE id=$4`,
			req.Title, req.Body, req.CoverImage, id, req.CanonicalURL, req.Sensitive,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		if err := upsertTags(r.Context(), d, id, req.Tags); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		if d.Search != nil {
			var state, slug, authorUsername, authorDisplayName string
			var body, publishedAt *string
			_ = d.Pool.QueryRow(r.Context(),
				`SELECT p.state, p.slug, p.body, p.published_at::text, u.username, u.display_name
				 FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1`, id,
			).Scan(&state, &slug, &body, &publishedAt, &authorUsername, &authorDisplayName)
			if state == "published" {
				var tagNames []string
				tagRows, _ := d.Pool.Query(r.Context(),
					`SELECT t.name FROM tags t JOIN post_tags pt ON pt.tag_id = t.id WHERE pt.post_id = $1`, id)
				if tagRows != nil {
					for tagRows.Next() {
						var name string
						if tagRows.Scan(&name) == nil {
							tagNames = append(tagNames, name)
						}
					}
					tagRows.Close()
				}
				bodyStr := ""
				if body != nil {
					bodyStr = *body
				}
				pubAt := ""
				if publishedAt != nil {
					pubAt = *publishedAt
				}
				_ = d.Search.IndexPost(search.PostDocument{
					ID:                id,
					Title:             req.Title,
					Body:              bodyStr,
					AuthorUsername:    authorUsername,
					AuthorDisplayName: authorDisplayName,
					Tags:              tagNames,
					PublishedAt:       pubAt,
					Slug:              slug,
				})
			}
		}

		writeJSON(w, http.StatusOK, map[string]string{"id": id})
	}
}

func DeletePost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id := r.PathValue("id")

		var authorUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1`, id,
		).Scan(&authorUsername)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found"})
			return
		}
		if authorUsername != claims.Sub && !auth.HasRole(claims.Role, "moderator") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		_, _ = d.Pool.Exec(r.Context(), `DELETE FROM posts WHERE id=$1`, id)
		if d.Search != nil {
			_ = d.Search.DeletePost(id)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
