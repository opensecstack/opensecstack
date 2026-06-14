package handlers

import (
	"net/http"
	"strconv"

	"github.com/opensecstack/community/internal/api/middleware"
)

type templateRow struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Tags      []string `json:"tags"`
	CreatedAt string   `json:"created_at"`
}

func ListTemplates(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, claims.Sub,
		).Scan(&userID); err != nil {
			writeJSON(w, http.StatusOK, []templateRow{})
			return
		}

		rows, err := d.Pool.Query(r.Context(),
			`SELECT id, name, title, body, tags, created_at::text
			 FROM post_templates
			 WHERE user_id = $1
			 ORDER BY created_at DESC`,
			userID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		templates := []templateRow{}
		for rows.Next() {
			var t templateRow
			var tags []string
			if err := rows.Scan(&t.ID, &t.Name, &t.Title, &t.Body, &tags, &t.CreatedAt); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			t.Tags = tags
			templates = append(templates, t)
		}
		writeJSON(w, http.StatusOK, templates)
	}
}

func CreateTemplate(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var req struct {
			Name  string   `json:"name"`
			Title string   `json:"title"`
			Body  string   `json:"body"`
			Tags  []string `json:"tags"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if req.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
			return
		}
		if req.Tags == nil {
			req.Tags = []string{}
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, claims.Sub,
		).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		var t templateRow
		var tags []string
		err := d.Pool.QueryRow(r.Context(),
			`INSERT INTO post_templates (user_id, name, title, body, tags)
			 VALUES ($1, $2, $3, $4, $5)
			 RETURNING id, name, title, body, tags, created_at::text`,
			userID, req.Name, req.Title, req.Body, req.Tags,
		).Scan(&t.ID, &t.Name, &t.Title, &t.Body, &tags, &t.CreatedAt)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		t.Tags = tags
		writeJSON(w, http.StatusCreated, t)
	}
}

func DeleteTemplate(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		idStr := r.PathValue("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid template id"})
			return
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, claims.Sub,
		).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		tag, err := d.Pool.Exec(r.Context(),
			`DELETE FROM post_templates WHERE id=$1 AND user_id=$2`,
			id, userID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "template not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
