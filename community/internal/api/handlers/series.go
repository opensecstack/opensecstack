package handlers

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
)

type seriesPostEntry struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Slug     string `json:"slug"`
	Position int    `json:"position"`
}

type seriesResponse struct {
	ID             string            `json:"id"`
	Title          string            `json:"title"`
	Slug           string            `json:"slug"`
	Description    string            `json:"description"`
	CreatedAt      string            `json:"created_at"`
	AuthorUsername string            `json:"author_username"`
	AuthorName     string            `json:"author_name"`
	Posts          []seriesPostEntry `json:"posts"`
}

type seriesListItem struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	PostCount   int64  `json:"post_count"`
}

func CreateSeries(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if !auth.HasRole(claims.Role, "author") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		var req struct {
			Title       string `json:"title"`
			Description string `json:"description"`
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
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, claims.Sub,
		).Scan(&authorID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		var id string
		if err := d.Pool.QueryRow(r.Context(),
			`INSERT INTO series (author_id, title, slug, description) VALUES ($1,$2,$3,$4) RETURNING id`,
			authorID, req.Title, slug, req.Description,
		).Scan(&id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{"id": id, "slug": slug})
	}
}

func GetSeries(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")

		rows, err := d.Pool.Query(r.Context(), `
			SELECT s.id, s.title, s.slug, s.description, s.created_at::text,
			       u.username, u.display_name,
			       p.id, p.title, p.slug, sp.position
			FROM series s
			JOIN users u ON u.id = s.author_id
			LEFT JOIN series_posts sp ON sp.series_id = s.id
			LEFT JOIN posts p ON p.id = sp.post_id AND p.state = 'published'
			WHERE s.slug = $1
			ORDER BY sp.position ASC`, slug)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var result *seriesResponse
		for rows.Next() {
			var (
				sID, sTitle, sSlug, sDesc, sCreatedAt string
				uUsername, uDisplayName               string
				pID, pTitle, pSlug                    *string
				pPosition                             *int
			)
			if err := rows.Scan(
				&sID, &sTitle, &sSlug, &sDesc, &sCreatedAt,
				&uUsername, &uDisplayName,
				&pID, &pTitle, &pSlug, &pPosition,
			); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			if result == nil {
				result = &seriesResponse{
					ID:             sID,
					Title:          sTitle,
					Slug:           sSlug,
					Description:    sDesc,
					CreatedAt:      sCreatedAt,
					AuthorUsername: uUsername,
					AuthorName:     uDisplayName,
					Posts:          []seriesPostEntry{},
				}
			}
			if pID != nil && pTitle != nil && pSlug != nil && pPosition != nil {
				result.Posts = append(result.Posts, seriesPostEntry{
					ID:       *pID,
					Title:    *pTitle,
					Slug:     *pSlug,
					Position: *pPosition,
				})
			}
		}

		if result == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "series not found"})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func AddPostToSeries(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		seriesID := r.PathValue("id")

		var req struct {
			PostID   string `json:"post_id"`
			Position int    `json:"position"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		var authorID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT author_id FROM series WHERE id = $1`, seriesID,
		).Scan(&authorID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "series not found"})
			return
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, claims.Sub,
		).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		if authorID != userID {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		_, err := d.Pool.Exec(r.Context(),
			`INSERT INTO series_posts (series_id, post_id, position) VALUES ($1,$2,$3)
			 ON CONFLICT (series_id, post_id) DO UPDATE SET position=$3`,
			seriesID, req.PostID, req.Position,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func RemovePostFromSeries(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		seriesID := r.PathValue("id")
		postID := r.PathValue("post_id")

		var authorID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT author_id FROM series WHERE id = $1`, seriesID,
		).Scan(&authorID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "series not found"})
			return
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, claims.Sub,
		).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		if authorID != userID {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM series_posts WHERE series_id=$1 AND post_id=$2`, seriesID, postID,
		)
		w.WriteHeader(http.StatusNoContent)
	}
}

// Wire: mux.Handle("GET /api/v1/posts/{id}/series", optAuth(http.HandlerFunc(handlers.GetPostSeries(d))))
func GetPostSeries(d Deps) http.HandlerFunc {
	type postEntry struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Slug     string `json:"slug"`
		Position int    `json:"position"`
	}
	type seriesInfo struct {
		ID          string `json:"id"`
		Title       string `json:"title"`
		Slug        string `json:"slug"`
		Description string `json:"description"`
	}
	type response struct {
		Series          *seriesInfo `json:"series"`
		Posts           []postEntry `json:"posts"`
		CurrentPosition int         `json:"current_position"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		postID := r.PathValue("id")

		// Look up which series (if any) this post belongs to.
		var seriesID string
		var currentPosition int
		err := d.Pool.QueryRow(r.Context(),
			`SELECT sp.series_id, sp.position
			 FROM series_posts sp
			 JOIN posts p ON p.id = sp.post_id
			 WHERE sp.post_id = $1`, postID,
		).Scan(&seriesID, &currentPosition)
		if err != nil {
			// Post is not in any series — return null series, 200.
			writeJSON(w, http.StatusOK, response{Series: nil, Posts: []postEntry{}, CurrentPosition: 0})
			return
		}

		// Fetch series metadata.
		var s seriesInfo
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id, title, slug, COALESCE(description, '') FROM series WHERE id = $1`, seriesID,
		).Scan(&s.ID, &s.Title, &s.Slug, &s.Description); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// Fetch all published posts in the series ordered by position.
		rows, err := d.Pool.Query(r.Context(),
			`SELECT p.id, p.title, p.slug, sp.position
			 FROM series_posts sp
			 JOIN posts p ON p.id = sp.post_id AND p.state = 'published'
			 WHERE sp.series_id = $1
			 ORDER BY sp.position ASC`, seriesID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		posts := []postEntry{}
		for rows.Next() {
			var pe postEntry
			if err := rows.Scan(&pe.ID, &pe.Title, &pe.Slug, &pe.Position); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			posts = append(posts, pe)
		}

		writeJSON(w, http.StatusOK, response{
			Series:          &s,
			Posts:           posts,
			CurrentPosition: currentPosition,
		})
	}
}

func ListMySeries(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		rows, err := d.Pool.Query(r.Context(), `
			SELECT s.id, s.title, s.slug, s.description, s.created_at::text, count(sp.post_id) AS post_count
			FROM series s
			LEFT JOIN series_posts sp ON sp.series_id = s.id
			JOIN users u ON u.id = s.author_id AND u.username = $1
			GROUP BY s.id
			ORDER BY s.created_at DESC`, claims.Sub)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		items := []seriesListItem{}
		for rows.Next() {
			var item seriesListItem
			if err := rows.Scan(&item.ID, &item.Title, &item.Slug, &item.Description, &item.CreatedAt, &item.PostCount); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			items = append(items, item)
		}
		writeJSON(w, http.StatusOK, items)
	}
}

func UpdateSeriesPostPosition(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		seriesID := r.PathValue("id")
		postID := r.PathValue("post_id")

		// verify ownership
		var ownerUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM series s JOIN users u ON u.id=s.author_id WHERE s.id=$1`, seriesID).Scan(&ownerUsername)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if ownerUsername != claims.Sub {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		var req struct {
			Position int `json:"position"`
		}
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		_, err = d.Pool.Exec(r.Context(),
			`UPDATE series_posts SET position=$1 WHERE series_id=$2 AND post_id=$3`,
			req.Position, seriesID, postID)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
