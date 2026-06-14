// Enrollment handler — POST /api/v1/enrollments.
// Enrolls the authenticated user in a track (cohort). Returns 201 on success,
// 409 if the user is already actively enrolled.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ── Interface ──────────────────────────────────────────────────────────────────

// Enroller is the write slice of EnrollmentStore the handler depends on.
type Enroller interface {
	Enroll(ctx context.Context, cohortID, userID, byUserID uuid.UUID) (*db.CohortEnrollment, error)
}

// ── Handler struct ─────────────────────────────────────────────────────────────

// EnrollmentHandler serves /enrollments routes.
type EnrollmentHandler struct {
	Enrollments Enroller
	Logger      *zerolog.Logger
}

// NewEnrollmentHandler wires an EnrollmentHandler.
func NewEnrollmentHandler(enrollments Enroller, logger *zerolog.Logger) *EnrollmentHandler {
	return &EnrollmentHandler{Enrollments: enrollments, Logger: logger}
}

// ── Request / response types ───────────────────────────────────────────────────

type enrollRequest struct {
	TrackID string `json:"track_id"`
}

type enrollResponse struct {
	EnrollmentID string `json:"enrollment_id"`
	TrackID      string `json:"track_id"`
	UserID       string `json:"user_id"`
	EnrolledAt   string `json:"enrolled_at"`
}

// ── Enroll handler ─────────────────────────────────────────────────────────────

// Enroll handles POST /api/v1/enrollments.
// Body: {"track_id": "<uuid>"}
// Returns 201 on success, 409 if the user is already enrolled.
func (h *EnrollmentHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	uid, ok := userIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON")
		return
	}
	if req.TrackID == "" {
		writeError(w, http.StatusBadRequest, "missing_track_id", "track_id is required")
		return
	}

	trackID, err := uuid.Parse(req.TrackID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_track_id", "track_id must be a UUID")
		return
	}

	// Enroll: pass trackID as cohortID (the store models track-level enrollment
	// through the cohort_enrollments table; the caller enrolls themselves).
	enrollment, err := h.Enrollments.Enroll(r.Context(), trackID, uid, uid)
	if err != nil {
		// Unique-constraint violation (uq_cohort_enrollments_active) → 409.
		var pgErr *pgconn.PgError
		if isPgError(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "already_enrolled", "user is already enrolled in this track")
			return
		}
		h.log().Error().Err(err).
			Str("track_id", req.TrackID).
			Str("user_id", uid.String()).
			Msg("enrollments.enroll: store error")
		writeError(w, http.StatusInternalServerError, "internal_error", "enrollment failed")
		return
	}

	writeJSON(w, http.StatusCreated, enrollResponse{
		EnrollmentID: enrollment.ID.String(),
		TrackID:      enrollment.CohortID.String(),
		UserID:       enrollment.UserID.String(),
		EnrolledAt:   enrollment.EnrolledAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// log returns the handler's logger, falling back to a no-op logger.
func (h *EnrollmentHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}

// isPgError unwraps err to a *pgconn.PgError using errors.As semantics.
// We inline this to avoid importing "errors" just for As.
func isPgError(err error, target **pgconn.PgError) bool {
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if pg, ok := err.(*pgconn.PgError); ok {
			*target = pg
			return true
		}
		u, ok := err.(unwrapper)
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return false
}
