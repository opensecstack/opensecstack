package handlers

// Wire in server.go:
//   mux.Handle("POST /api/v1/admin/tags", auth(http.HandlerFunc(handlers.AdminCreateTag(d))))
//   mux.Handle("PUT /api/v1/admin/tags/{slug}", auth(http.HandlerFunc(handlers.AdminUpdateTag(d))))
//   mux.Handle("DELETE /api/v1/admin/tags/{slug}", auth(http.HandlerFunc(handlers.AdminDeleteTag(d))))

import (
	"net/http"
	"regexp"
	"strings"
)

var nonAlphanumHyphen = regexp.MustCompile(`[^a-z0-9-]+`)

func slugFromName(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.ReplaceAll(s, " ", "-")
	s = nonAlphanumHyphen.ReplaceAllString(s, "")
	s = strings.Trim(s, "-")
	return s
}

var validHexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// AdminCreateTag handles POST /api/v1/admin/tags.
func AdminCreateTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Color       string `json:"color"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
			return
		}

		if req.Color == "" {
			req.Color = "#6366f1"
		} else if !validHexColor.MatchString(req.Color) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "color must be a valid hex color (#rrggbb)"})
			return
		}

		slug := slugFromName(req.Name)
		if slug == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name produces an empty slug"})
			return
		}

		var t tagRow
		err := d.Pool.QueryRow(r.Context(), `
INSERT INTO tags (name, slug, description, color)
VALUES ($1, $2, $3, $4)
RETURNING id, name, slug, description, color, 0::bigint, 0::bigint`,
			req.Name, slug, req.Description, req.Color,
		).Scan(&t.ID, &t.Name, &t.Slug, &t.Description, &t.Color, &t.PostCount, &t.FollowerCount)
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "duplicate") || strings.Contains(errStr, "unique") {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "a tag with that name or slug already exists"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": errStr})
			return
		}

		writeJSON(w, http.StatusCreated, t)
	}
}

// AdminUpdateTag handles PUT /api/v1/admin/tags/{slug}.
func AdminUpdateTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		currentSlug := r.PathValue("slug")

		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Color       string `json:"color"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
			return
		}

		if req.Color == "" {
			req.Color = "#6366f1"
		} else if !validHexColor.MatchString(req.Color) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "color must be a valid hex color (#rrggbb)"})
			return
		}

		newSlug := slugFromName(req.Name)
		if newSlug == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name produces an empty slug"})
			return
		}

		var t tagRow
		err := d.Pool.QueryRow(r.Context(), `
UPDATE tags
SET name=$1, slug=$2, description=$3, color=$4
WHERE slug=$5
RETURNING id, name, slug, description, color,
          (SELECT count(*) FROM post_tags pt
           JOIN posts p ON p.id = pt.post_id AND p.state = 'published'
           WHERE pt.tag_id = tags.id)::bigint,
          (SELECT count(*) FROM tag_follows tf WHERE tf.tag_id = tags.id)::bigint`,
			req.Name, newSlug, req.Description, req.Color, currentSlug,
		).Scan(&t.ID, &t.Name, &t.Slug, &t.Description, &t.Color, &t.PostCount, &t.FollowerCount)
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "no rows") {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "tag not found"})
				return
			}
			if strings.Contains(errStr, "duplicate") || strings.Contains(errStr, "unique") {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "a tag with that name or slug already exists"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": errStr})
			return
		}

		writeJSON(w, http.StatusOK, t)
	}
}

// AdminDeleteTag handles DELETE /api/v1/admin/tags/{slug}.
func AdminDeleteTag(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		slug := r.PathValue("slug")
		tag, err := d.Pool.Exec(r.Context(), `DELETE FROM tags WHERE slug=$1`, slug)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "tag not found"})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
