package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

// RequestDeletion handles POST /api/v1/me/deletion-request.
func RequestDeletion(d Deps) http.HandlerFunc {
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
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		// Check for existing pending request.
		var existingID string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM deletion_requests WHERE user_id=$1 AND status='pending'`, userID,
		).Scan(&existingID)
		if err == nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "deletion already requested"})
			return
		}

		var scheduledFor string
		if err := d.Pool.QueryRow(r.Context(),
			`INSERT INTO deletion_requests (user_id) VALUES ($1) RETURNING scheduled_for::text`, userID,
		).Scan(&scheduledFor); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusCreated, map[string]string{
			"scheduled_for": scheduledFor,
			"message":       "Your account will be deleted in 30 days. You can cancel before then.",
		})
	}
}

// CancelDeletion handles DELETE /api/v1/me/deletion-request.
func CancelDeletion(d Deps) http.HandlerFunc {
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
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`UPDATE deletion_requests SET status='cancelled' WHERE user_id=$1 AND status='pending'`, userID,
		)

		w.WriteHeader(http.StatusNoContent)
	}
}

type deletionRequestRow struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	RequestedAt  string `json:"requested_at"`
	ScheduledFor string `json:"scheduled_for"`
}

// GetDeletionStatus handles GET /api/v1/me/deletion-request.
func GetDeletionStatus(d Deps) http.HandlerFunc {
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
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		var req deletionRequestRow
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id, status, requested_at::text, scheduled_for::text
			 FROM deletion_requests
			 WHERE user_id=$1 AND status='pending'
			 ORDER BY requested_at DESC LIMIT 1`, userID,
		).Scan(&req.ID, &req.Status, &req.RequestedAt, &req.ScheduledFor)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"request": nil})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"request": req})
	}
}

type adminDeletionRequestRow struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	RequestedAt  string `json:"requested_at"`
	ScheduledFor string `json:"scheduled_for"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
}

// AdminListDeletionRequests handles GET /api/v1/admin/deletion-requests.
func AdminListDeletionRequests(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		rows, err := d.Pool.Query(r.Context(), `
SELECT dr.id, dr.status, dr.requested_at::text, dr.scheduled_for::text,
       u.username, u.email, u.display_name
FROM deletion_requests dr
JOIN users u ON u.id = dr.user_id
WHERE dr.status = 'pending'
ORDER BY dr.scheduled_for ASC`)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var requests []adminDeletionRequestRow
		for rows.Next() {
			var req adminDeletionRequestRow
			if err := rows.Scan(
				&req.ID, &req.Status, &req.RequestedAt, &req.ScheduledFor,
				&req.Username, &req.Email, &req.DisplayName,
			); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			requests = append(requests, req)
		}
		if requests == nil {
			requests = []adminDeletionRequestRow{}
		}

		writeJSON(w, http.StatusOK, map[string]any{"requests": requests})
	}
}

// AdminProcessDeletion handles POST /api/v1/admin/deletion-requests/{id}/process.
func AdminProcessDeletion(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		id := r.PathValue("id")

		var userID, status string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT user_id, status FROM deletion_requests WHERE id=$1`, id,
		).Scan(&userID, &status); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "deletion request not found"})
			return
		}
		if status != "pending" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request is not pending"})
			return
		}

		// Delete the user — cascades to all their content.
		if _, err := d.Pool.Exec(r.Context(),
			`DELETE FROM users WHERE id=$1`, userID,
		); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// Mark the request as processed.
		_, _ = d.Pool.Exec(r.Context(),
			`UPDATE deletion_requests SET status='processed', processed_at=now() WHERE id=$1`, id,
		)

		w.WriteHeader(http.StatusNoContent)
	}
}
