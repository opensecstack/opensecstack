package handlers

import (
	"net/http"
	"time"

	"github.com/opensecstack/community/internal/api/middleware"
)

// adminUser is the shape returned by ListAdminUsers.
type adminUser struct {
	ID            string  `json:"id"`
	Username      string  `json:"username"`
	DisplayName   string  `json:"display_name"`
	Email         *string `json:"email"`
	Role          string  `json:"role"`
	CreatedAt     string  `json:"created_at"`
	PostCount     int     `json:"post_count"`
	PlatformBadge *string `json:"platform_badge"`
	DeactivatedAt *string `json:"deactivated_at"`
}

// ListAdminUsers handles GET /api/v1/admin/users.
func ListAdminUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		limit := queryInt(r, "limit", 50)
		offset := queryInt(r, "offset", 0)

		rows, err := d.Pool.Query(r.Context(), `
SELECT u.id, u.username, u.display_name, u.email, u.role, u.created_at::text,
       (SELECT count(*) FROM posts p WHERE p.author_id = u.id AND p.state = 'published') AS post_count,
       u.platform_badge,
       u.deactivated_at::text
FROM users u
ORDER BY u.created_at DESC
LIMIT $1 OFFSET $2`, limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var users []adminUser
		for rows.Next() {
			var u adminUser
			if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role, &u.CreatedAt, &u.PostCount, &u.PlatformBadge, &u.DeactivatedAt); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			users = append(users, u)
		}
		if users == nil {
			users = []adminUser{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users, "count": len(users)})
	}
}

// SetUserRole handles PUT /api/v1/admin/users/{username}/role.
func SetUserRole(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		claims := middleware.ClaimsFrom(r.Context())
		targetUsername := r.PathValue("username")

		if claims.Sub == targetUsername {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot change own role"})
			return
		}

		var req struct {
			Role string `json:"role"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		validRoles := map[string]bool{
			"viewer":    true,
			"author":    true,
			"moderator": true,
			"admin":     true,
		}
		if !validRoles[req.Role] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid role"})
			return
		}

		tag, err := d.Pool.Exec(r.Context(),
			`UPDATE users SET role=$1, updated_at=now() WHERE username=$2`,
			req.Role, targetUsername,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		var actorID string
		_ = d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&actorID)
		recordAudit(r.Context(), d.Pool, actorID, "set_role", "user", targetUsername, req.Role)
		w.WriteHeader(http.StatusNoContent)
	}
}

// broadcastRow is the shape returned by GetBroadcast.
type broadcastRow struct {
	ID        string  `json:"id"`
	Body      string  `json:"body"`
	LinkURL   *string `json:"link_url"`
	CreatedAt string  `json:"created_at"`
}

// GetBroadcast handles GET /api/v1/broadcasts (public).
func GetBroadcast(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b broadcastRow
		err := d.Pool.QueryRow(r.Context(), `
SELECT id, body, link_url, created_at::text
FROM broadcasts
WHERE active = true AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at DESC
LIMIT 1`).Scan(&b.ID, &b.Body, &b.LinkURL, &b.CreatedAt)
		if err != nil {
			// No active broadcast — return null without an error status.
			writeJSON(w, http.StatusOK, map[string]any{"broadcast": nil})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"broadcast": b})
	}
}

// CreateBroadcast handles POST /api/v1/admin/broadcasts.
func CreateBroadcast(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		claims := middleware.ClaimsFrom(r.Context())

		var req struct {
			Body      string  `json:"body"`
			LinkURL   *string `json:"link_url"`
			ExpiresAt string  `json:"expires_at"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if req.Body == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body is required"})
			return
		}

		// Resolve caller's user ID.
		var callerID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, claims.Sub,
		).Scan(&callerID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not resolve caller"})
			return
		}

		// Parse optional expires_at.
		var expiresAt *time.Time
		if req.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339, req.ExpiresAt)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expires_at must be RFC3339"})
				return
			}
			expiresAt = &t
		}

		var id string
		if err := d.Pool.QueryRow(r.Context(), `
INSERT INTO broadcasts (body, link_url, created_by, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id`,
			req.Body, req.LinkURL, callerID, expiresAt,
		).Scan(&id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

// DeleteBroadcast handles DELETE /api/v1/admin/broadcasts/{id}.
func DeleteBroadcast(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		id := r.PathValue("id")
		_, err := d.Pool.Exec(r.Context(),
			`UPDATE broadcasts SET active=false WHERE id=$1`, id,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
