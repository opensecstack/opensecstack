package handlers

import (
	"net/http"
	"strings"

	"github.com/opensecstack/community/internal/api/middleware"
)

type modNoteRow struct {
	ID             string `json:"id"`
	Body           string `json:"body"`
	AuthorUsername string `json:"author_username"`
	CreatedAt      string `json:"created_at"`
}

// ListModNotes handles GET /api/v1/admin/users/{username}/notes.
// Returns all moderator notes written about a user. Requires moderator role.
func ListModNotes(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "moderator") {
			return
		}

		targetUsername := r.PathValue("username")

		rows, err := d.Pool.Query(r.Context(), `
SELECT mn.id, mn.body, u.username AS author_username, mn.created_at::text
FROM user_mod_notes mn
JOIN users u ON u.id = mn.author_id
JOIN users s ON s.id = mn.subject_id
WHERE s.username = $1
ORDER BY mn.created_at DESC`, targetUsername)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		notes := []modNoteRow{}
		for rows.Next() {
			var n modNoteRow
			if err := rows.Scan(&n.ID, &n.Body, &n.AuthorUsername, &n.CreatedAt); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			notes = append(notes, n)
		}

		writeJSON(w, http.StatusOK, notes)
	}
}

// CreateModNote handles POST /api/v1/admin/users/{username}/notes.
// Creates a new moderator note about a user. Requires moderator role.
func CreateModNote(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "moderator") {
			return
		}

		claims := middleware.ClaimsFrom(r.Context())
		targetUsername := r.PathValue("username")

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

		// Resolve author ID from JWT subject.
		var authorID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, claims.Sub,
		).Scan(&authorID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not resolve author"})
			return
		}

		// Resolve subject (target) user ID.
		var subjectID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, targetUsername,
		).Scan(&subjectID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		var id string
		if err := d.Pool.QueryRow(r.Context(), `
INSERT INTO user_mod_notes (subject_id, author_id, body)
VALUES ($1, $2, $3)
RETURNING id`,
			subjectID, authorID, strings.TrimSpace(req.Body),
		).Scan(&id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

// DeleteModNote handles DELETE /api/v1/admin/notes/{id}.
// Deletes a moderator note by ID. Requires moderator role.
func DeleteModNote(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "moderator") {
			return
		}

		id := r.PathValue("id")
		tag, err := d.Pool.Exec(r.Context(),
			`DELETE FROM user_mod_notes WHERE id=$1`, id,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "note not found"})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
