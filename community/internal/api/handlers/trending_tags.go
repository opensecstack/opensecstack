package handlers

import (
	"net/http"
)

type trendingTagRow struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Color     string `json:"color"`
	PostCount int64  `json:"post_count"`
}

func GetTrendingTags(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := d.Pool.Query(r.Context(), `
			SELECT t.id, t.name, t.slug, t.color, COUNT(pt.post_id) AS post_count
			FROM tags t
			JOIN post_tags pt ON pt.tag_id = t.id
			JOIN posts p ON p.id = pt.post_id
			WHERE p.state = 'published'
			  AND p.created_at >= now() - INTERVAL '7 days'
			GROUP BY t.id, t.name, t.slug, t.color
			ORDER BY post_count DESC
			LIMIT 8`)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		tags := []trendingTagRow{}
		for rows.Next() {
			var t trendingTagRow
			if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Color, &t.PostCount); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			tags = append(tags, t)
		}

		writeJSON(w, http.StatusOK, map[string]any{"tags": tags})
	}
}
