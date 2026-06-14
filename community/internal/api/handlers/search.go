package handlers

import (
	"fmt"
	"net/http"
	"strings"
)

func Search(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)
		tag := r.URL.Query().Get("tag")
		author := r.URL.Query().Get("author")
		from := strings.TrimSpace(r.URL.Query().Get("from"))
		to := strings.TrimSpace(r.URL.Query().Get("to"))

		// Require at least one of q, tag, or author.
		if q == "" && tag == "" && author == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one of q, tag, or author is required"})
			return
		}

		if d.Search != nil && q != "" {
			// Meilisearch path: use Meilisearch for text ranking, then filter by
			// tag/author in Postgres when fetching the matched IDs.
			// Note: from/to date filters are applied in the Postgres step below,
			// but Meilisearch ranking is not date-aware — results are ranked by
			// relevance and then filtered by date in Postgres.
			ids, err := d.Search.Search(q, limit, offset)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}

			if len(ids) == 0 {
				writeJSON(w, http.StatusOK, postListResponse{Posts: []postRow{}, Count: 0})
				return
			}

			sql, args := buildListByIDsQuery(ids, tag, author, from, to)
			rows, err := d.Pool.Query(r.Context(), sql, args...)
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
			return
		}

		// PostgreSQL fallback: build the search query dynamically.
		sql, args := buildSearchQuery(q, tag, author, from, to, limit, offset)
		rows, err := d.Pool.Query(r.Context(), sql, args...)
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

// buildSearchQuery constructs a dynamic PostgreSQL FTS query with optional tag, author,
// and date-range filters. q may be empty when only tag/author/date filters are provided.
func buildSearchQuery(q, tag, author, from, to string, limit, offset int) (string, []any) {
	// The SELECT and base FROM/JOIN are constant. We alias the tag join used for
	// display as "t" and use dedicated aliases for the filter joins.
	var sb strings.Builder
	args := make([]any, 0, 7)

	sb.WriteString(`
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
		LEFT JOIN post_tags pt ON pt.post_id = p.id
		LEFT JOIN tags t ON t.id = pt.tag_id`)

	// Tag filter: inner join to ensure the post has the requested tag.
	if tag != "" {
		args = append(args, slugify(tag))
		n := len(args)
		sb.WriteString(fmt.Sprintf(`
		JOIN post_tags pt_f ON pt_f.post_id = p.id
		JOIN tags t_f ON t_f.id = pt_f.tag_id AND t_f.slug = $%d`, n))
	}

	sb.WriteString("\n\t\tWHERE p.state = 'published'")

	// Full-text search clause.
	if q != "" {
		args = append(args, q)
		n := len(args)
		sb.WriteString(fmt.Sprintf(` AND p.search_vector @@ plainto_tsquery('english', $%d)`, n))
	}

	// Author filter.
	if author != "" {
		args = append(args, strings.TrimSpace(author))
		n := len(args)
		sb.WriteString(fmt.Sprintf(` AND u.username = $%d`, n))
	}

	// Date-range filters.
	if from != "" {
		args = append(args, from)
		n := len(args)
		sb.WriteString(fmt.Sprintf(` AND p.published_at >= $%d::date`, n))
	}
	if to != "" {
		args = append(args, to)
		n := len(args)
		sb.WriteString(fmt.Sprintf(` AND p.published_at <= ($%d::date + interval '1 day')`, n))
	}

	sb.WriteString("\n\t\tGROUP BY p.id, u.id")

	// ORDER BY: rank by relevance when a text query is present, otherwise by date.
	if q != "" {
		args = append(args, q)
		n := len(args)
		sb.WriteString(fmt.Sprintf(`
		ORDER BY ts_rank(p.search_vector, plainto_tsquery('english', $%d)) DESC`, n))
	} else {
		sb.WriteString(`
		ORDER BY p.pinned DESC, p.published_at DESC`)
	}

	args = append(args, limit, offset)
	limitN := len(args) - 1
	offsetN := len(args)
	sb.WriteString(fmt.Sprintf(`
		LIMIT $%d OFFSET $%d`, limitN, offsetN))

	return sb.String(), args
}

// buildListByIDsQuery builds a filtered query for the Meilisearch path.
// The Meilisearch IDs are passed as $1; tag, author, and date filters occupy subsequent params.
// Note: Meilisearch ranking is not date-aware; date filters are applied here in Postgres only.
func buildListByIDsQuery(ids []string, tag, author, from, to string) (string, []any) {
	args := []any{ids}

	var sb strings.Builder
	sb.WriteString(`
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
		LEFT JOIN post_tags pt ON pt.post_id = p.id
		LEFT JOIN tags t ON t.id = pt.tag_id`)

	if tag != "" {
		args = append(args, slugify(tag))
		n := len(args)
		sb.WriteString(fmt.Sprintf(`
		JOIN post_tags pt_f ON pt_f.post_id = p.id
		JOIN tags t_f ON t_f.id = pt_f.tag_id AND t_f.slug = $%d`, n))
	}

	sb.WriteString("\n\t\tWHERE p.state = 'published' AND p.id = ANY($1)")

	if author != "" {
		args = append(args, strings.TrimSpace(author))
		n := len(args)
		sb.WriteString(fmt.Sprintf(` AND u.username = $%d`, n))
	}

	// Date-range filters.
	if from != "" {
		args = append(args, from)
		n := len(args)
		sb.WriteString(fmt.Sprintf(` AND p.published_at >= $%d::date`, n))
	}
	if to != "" {
		args = append(args, to)
		n := len(args)
		sb.WriteString(fmt.Sprintf(` AND p.published_at <= ($%d::date + interval '1 day')`, n))
	}

	sb.WriteString("\n\t\tGROUP BY p.id, u.id")

	return sb.String(), args
}
