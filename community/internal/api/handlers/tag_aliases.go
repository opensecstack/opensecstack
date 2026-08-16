package handlers

import (
	"net/http"
)

// resolveTagSlug resolves a slug or alias to the canonical tag slug and id.
// Returns the canonical slug and tag id, or an error if not found.
func resolveTagSlug(r *http.Request, d Deps, input string) (slug string, id string, err error) {
	err = d.Pool.QueryRow(r.Context(),
		`SELECT slug, id FROM tags WHERE slug = $1`, input).Scan(&slug, &id)
	if err == nil {
		return slug, id, nil
	}
	// Try alias
	err = d.Pool.QueryRow(r.Context(),
		`SELECT t.slug, t.id FROM tag_aliases ta JOIN tags t ON t.id = ta.tag_id WHERE ta.alias = $1`, input).
		Scan(&slug, &id)
	return
}

type tagAliasItem struct {
	Alias   string `json:"alias"`
	TagSlug string `json:"tag_slug"`
}

// AdminListTagAliases handles GET /api/v1/admin/tags/{slug}/aliases.
func AdminListTagAliases(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}
		slug := r.PathValue("slug")
		rows, err := d.Pool.Query(r.Context(),
			`SELECT ta.alias FROM tag_aliases ta JOIN tags t ON t.id = ta.tag_id WHERE t.slug = $1 ORDER BY ta.alias`, slug)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		defer rows.Close()
		aliases := []tagAliasItem{}
		for rows.Next() {
			var a tagAliasItem
			if err := rows.Scan(&a.Alias); err != nil {
				continue
			}
			a.TagSlug = slug
			aliases = append(aliases, a)
		}
		writeJSON(w, http.StatusOK, map[string]any{"aliases": aliases})
	}
}

// AdminCreateTagAlias handles POST /api/v1/admin/tags/{slug}/aliases.
func AdminCreateTagAlias(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}
		slug := r.PathValue("slug")
		var req struct {
			Alias string `json:"alias"`
		}
		if err := decodeJSON(r, &req); err != nil || req.Alias == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		_, err := d.Pool.Exec(r.Context(),
			`INSERT INTO tag_aliases (alias, tag_id)
			 SELECT $1, id FROM tags WHERE slug = $2
			 ON CONFLICT DO NOTHING`, req.Alias, slug)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// AdminDeleteTagAlias handles DELETE /api/v1/admin/tags/aliases/{alias}.
func AdminDeleteTagAlias(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}
		alias := r.PathValue("alias")
		_, _ = d.Pool.Exec(r.Context(), `DELETE FROM tag_aliases WHERE alias = $1`, alias)
		w.WriteHeader(http.StatusNoContent)
	}
}
