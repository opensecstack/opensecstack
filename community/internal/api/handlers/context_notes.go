package handlers

import (
	"net/http"
	"strings"

	"github.com/opensecstack/community/internal/api/middleware"
)

// UpsertContextNote handles POST /api/v1/posts/{id}/context-note.
func UpsertContextNote(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "moderator") {
			return
		}

		postID := r.PathValue("id")

		var req struct {
			Body string `json:"body"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if strings.TrimSpace(req.Body) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body is required"})
			return
		}

		claims := middleware.ClaimsFrom(r.Context())

		var authorID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, claims.Sub,
		).Scan(&authorID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, err := d.Pool.Exec(r.Context(), `
INSERT INTO context_notes (post_id, body, author_id)
VALUES ($1, $2, $3)
ON CONFLICT (post_id) DO UPDATE SET body=$2, author_id=$3, updated_at=now()`,
			postID, req.Body, authorID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{
			"post_id": postID,
			"body":    req.Body,
		})
	}
}

// DeleteContextNote handles DELETE /api/v1/posts/{id}/context-note.
func DeleteContextNote(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "moderator") {
			return
		}

		postID := r.PathValue("id")
		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM context_notes WHERE post_id=$1`, postID,
		)

		w.WriteHeader(http.StatusNoContent)
	}
}

type contextNoteRow struct {
	ID             string `json:"id"`
	Body           string `json:"body"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	AuthorUsername string `json:"author_username"`
}

// GetContextNote handles GET /api/v1/posts/{id}/context-note (public).
func GetContextNote(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		postID := r.PathValue("id")

		var note contextNoteRow
		err := d.Pool.QueryRow(r.Context(), `
SELECT cn.id, cn.body, cn.created_at::text, cn.updated_at::text, u.username AS author_username
FROM context_notes cn
JOIN users u ON u.id = cn.author_id
WHERE cn.post_id=$1`, postID,
		).Scan(&note.ID, &note.Body, &note.CreatedAt, &note.UpdatedAt, &note.AuthorUsername)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"note": nil})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"note": note})
	}
}
