package handlers

import (
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/citadel"
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

		// Check for an existing request that hasn't reached a terminal state.
		var existingID string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM deletion_requests WHERE user_id=$1 AND status IN ('pending','approved')`, userID,
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
			"message":       "Your account will be deleted in 30 days, once an administrator approves the request. You can cancel before then.",
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
			`UPDATE deletion_requests SET status='cancelled' WHERE user_id=$1 AND status IN ('pending','approved')`, userID,
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
			 WHERE user_id=$1 AND status IN ('pending','approved')
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
// Includes both 'pending' (awaiting admin approval) and 'approved'
// (approved, awaiting scheduled_for or immediate processing) requests.
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
WHERE dr.status IN ('pending','approved')
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

// AdminApproveDeletion handles POST /api/v1/admin/deletion-requests/{id}/approve.
//
// This is the real second-person control (option (a) from the design
// notes, not a placeholder-Verifier fallback): a distinct admin identity
// must explicitly approve a pending GDPR erasure request before it can
// ever actually execute. Neither the scheduler's unattended sweep
// (scheduler.go's processDeletions) nor AdminProcessDeletion's immediate
// path will delete a user until status is 'approved' — this endpoint is
// the only way to reach that state. The pending -> approved transition
// mirrors the propose/approve shape irflow/internal/api/incidents.go uses
// for two-person action approval; RequestDeletion already plays the
// "propose" role (the user's own erasure request is the proposal), so
// this endpoint only needed to add "approve".
func AdminApproveDeletion(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}
		claims := middleware.ClaimsFrom(r.Context())
		id := r.PathValue("id")

		var requestUserID, status string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT user_id, status FROM deletion_requests WHERE id=$1`, id,
		).Scan(&requestUserID, &status); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "deletion request not found"})
			return
		}
		if status != "pending" {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "request is not pending"})
			return
		}

		var approverUserID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, claims.Sub,
		).Scan(&approverUserID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "approver account not found"})
			return
		}

		// Separation of duties: the approver (Verifier) must be a genuinely
		// different identity than the user being deleted (Actor). CITADEL's
		// Gate 3 NDS also HARD_STOPs on same-identity, but this is checked
		// here too, before ever mutating state — the same defense-in-depth
		// pattern apiguard's scans.go Approve() uses.
		if approverUserID == requestUserID {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "an admin cannot approve their own deletion request (separation of duties)",
			})
			return
		}

		tag, err := d.Pool.Exec(r.Context(),
			`UPDATE deletion_requests SET status='approved', approved_by=$1, approved_at=now() WHERE id=$2 AND status='pending'`,
			approverUserID, id,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "this deletion request was concurrently decided by someone else"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "approved"})
	}
}

// AdminProcessDeletion handles POST /api/v1/admin/deletion-requests/{id}/process.
// Immediately executes an already-approved deletion (rather than waiting
// for scheduled_for / the scheduler's sweep). Requires status='approved' —
// see AdminApproveDeletion — and, like the scheduler's processDeletions,
// evaluates a real Kerkese against CITADEL MARSHAL immediately before the
// DELETE; a REFUSE/HARD_STOP outcome blocks it.
func AdminProcessDeletion(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "admin") {
			return
		}

		id := r.PathValue("id")

		var userID, status string
		var userSinauthID, approvedBy, approverSinauthID sql.NullString
		if err := d.Pool.QueryRow(r.Context(), `
SELECT dr.user_id, dr.status, u.sinauth_id, dr.approved_by, au.sinauth_id
FROM deletion_requests dr
JOIN users u ON u.id = dr.user_id
LEFT JOIN users au ON au.id = dr.approved_by
WHERE dr.id=$1`, id,
		).Scan(&userID, &status, &userSinauthID, &approvedBy, &approverSinauthID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "deletion request not found"})
			return
		}
		if status != "approved" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "request is not approved — an admin must approve it first via POST /api/v1/admin/deletion-requests/{id}/approve",
			})
			return
		}

		reqUUID, err := uuid.Parse(id)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid deletion request id"})
			return
		}

		if d.Marshal != nil {
			actorID := citadel.ResolveIdentity(userSinauthID, userID)
			verifierID := "community-system-verifier"
			if approvedBy.Valid {
				verifierID = citadel.ResolveIdentity(approverSinauthID, approvedBy.String)
			}

			k := citadel.DeletionKerkese(d.Cfg.Node, reqUUID, actorID, verifierID)
			proceed, reasons, evalErr := d.Marshal.EvaluateDeletion(r.Context(), k)
			if evalErr != nil {
				slog.Warn("admin process deletion: CITADEL marshal evaluate failed — applying configured fail-mode",
					"user_id", userID, "request_id", id, "err", evalErr)
			}
			if !proceed {
				slog.Error("admin process deletion: CITADEL blocked GDPR deletion",
					"user_id", userID, "request_id", id, "reasons", reasons)
				writeJSON(w, http.StatusForbidden, map[string]string{"error": strings.Join(reasons, "; ")})
				return
			}
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

		if d.Citadel != nil {
			_ = d.Citadel.Emit(r.Context(), citadel.Event{
				Kind:      "community.user.deleted",
				NodeID:    d.Cfg.Node,
				Timestamp: time.Now(),
				Payload:   map[string]any{"user_id": userID, "request_id": id, "via": "admin_process"},
			})
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
