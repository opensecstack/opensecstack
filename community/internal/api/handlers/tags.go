package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/opensecstack/community/internal/db"
)

type tagRow struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	Description   string `json:"description"`
	Color         string `json:"color"`
	PostCount     int64  `json:"post_count"`
	FollowerCount int64  `json:"follower_count"`
}

type tagListResponse struct {
	Tags  []tagRow `json:"tags"`
	Count int      `json:"count"`
}

func ListTags(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := queryInt(r, "limit", 30)
		offset := queryInt(r, "offset", 0)
		rows, err := d.Pool.Query(r.Context(), db.QueryListTags, limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var tags []tagRow
		for rows.Next() {
			var t tagRow
			if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Description, &t.Color, &t.PostCount, &t.FollowerCount); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			tags = append(tags, t)
		}
		if tags == nil {
			tags = []tagRow{}
		}
		writeJSON(w, http.StatusOK, tagListResponse{Tags: tags, Count: len(tags)})
	}
}

func ListPostsByTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)

		// Resolve alias to canonical slug if needed.
		var tagID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM tags WHERE slug = $1`, slug).Scan(&tagID); err != nil {
			// Try alias
			var canonicalSlug string
			if err2 := d.Pool.QueryRow(r.Context(),
				`SELECT t.slug FROM tag_aliases ta JOIN tags t ON t.id = ta.tag_id WHERE ta.alias = $1`, slug).
				Scan(&canonicalSlug); err2 != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "tag not found"})
				return
			}
			slug = canonicalSlug
		}

		sort := r.URL.Query().Get("sort")
		rows, err := d.Pool.Query(r.Context(), db.SortedListPostsByTagQuery(sort), slug, limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var posts []postRow
		for rows.Next() {
			var p postRow
			var tags []string
			if err := rows.Scan(
				&p.ID, &p.AuthorID, &p.AuthorUsername, &p.AuthorName, &p.AuthorAvatar, &p.AuthorBadge,
				&p.Title, &p.Slug, &p.CoverImage, &p.State, &p.PublishedAt, &p.CreatedAt, &p.UpdatedAt,
				&tags, &p.ReactionCount, &p.CommentCount, &p.Views, &p.Locked,
			); err != nil {
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

func GetPopularTags(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 10
		rows, err := d.Pool.Query(r.Context(), `
			SELECT t.id, t.name, t.slug, t.color, COUNT(pt.post_id) AS post_count
			FROM tags t
			LEFT JOIN post_tags pt ON pt.tag_id = t.id
			LEFT JOIN posts p ON p.id = pt.post_id AND p.state = 'published'
			GROUP BY t.id
			ORDER BY post_count DESC, t.name ASC
			LIMIT $1
		`, limit)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"tags": []any{}})
			return
		}
		defer rows.Close()
		type tagItem struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Slug      string `json:"slug"`
			Color     string `json:"color"`
			PostCount int    `json:"post_count"`
		}
		var tags []tagItem
		for rows.Next() {
			var t tagItem
			rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Color, &t.PostCount)
			tags = append(tags, t)
		}
		if tags == nil {
			tags = []tagItem{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"tags": tags})
	}
}

func GetTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")

		// Resolve alias to canonical slug if needed.
		var canonicalSlug string
		err := d.Pool.QueryRow(r.Context(), `SELECT slug FROM tags WHERE slug = $1`, slug).Scan(&canonicalSlug)
		if err != nil {
			if err2 := d.Pool.QueryRow(r.Context(),
				`SELECT t.slug FROM tag_aliases ta JOIN tags t ON t.id = ta.tag_id WHERE ta.alias = $1`, slug).
				Scan(&canonicalSlug); err2 != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "tag not found"})
				return
			}
		}

		var t tagRow
		if err := d.Pool.QueryRow(r.Context(), db.QueryGetTag, canonicalSlug).
			Scan(&t.ID, &t.Name, &t.Slug, &t.Description, &t.Color, &t.PostCount, &t.FollowerCount); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "tag not found"})
			return
		}
		writeJSON(w, http.StatusOK, t)
	}
}

func upsertTags(ctx context.Context, d Deps, postID string, tagNames []string) error {
	if _, err := d.Pool.Exec(ctx, `DELETE FROM post_tags WHERE post_id=$1`, postID); err != nil {
		return err
	}
	for _, name := range tagNames {
		slug := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), " ", "-"))
		if slug == "" {
			continue
		}
		var tagID string
		err := d.Pool.QueryRow(ctx,
			`INSERT INTO tags (name, slug) VALUES ($1,$2) ON CONFLICT (slug) DO UPDATE SET name=EXCLUDED.name RETURNING id`,
			strings.TrimSpace(name), slug,
		).Scan(&tagID)
		if err != nil {
			return err
		}
		_, _ = d.Pool.Exec(ctx, `INSERT INTO post_tags (post_id,tag_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, postID, tagID)
	}
	return nil
}
