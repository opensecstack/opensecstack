// User progress + certifications handlers.
//
// v1.0.0 wires UsersHandler backed by ProgressStore + CertificationStore.
// The standalone UserProgress / UserCertifications HandlerFuncs are retained
// as nil-safe fallbacks so server.go can run without a DB connection.
package handlers

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ── interfaces ────────────────────────────────────────────────────────────────

// ProgressReader is the read slice of ProgressStore UsersHandler depends on.
type ProgressReader interface {
	GetByUser(ctx context.Context, userID uuid.UUID) ([]db.Progress, error)
}

// CertificationReader is the read slice of CertificationStore UsersHandler depends on.
type CertificationReader interface {
	ListByUser(ctx context.Context, userID uuid.UUID, includeExpired bool) ([]db.Certification, error)
}

// ── DB-backed handler (v1.0.0) ────────────────────────────────────────────────

// UsersHandler serves /users routes from the DB stores.
type UsersHandler struct {
	ProgressStore      ProgressReader
	CertificationStore CertificationReader
	Lessons            LessonReaderForHandler // optional — resolves lesson metadata
	Audit              *db.AuditEventStore    // optional
	Logger             *zerolog.Logger
}

// NewUsersHandler wires a UsersHandler.
func NewUsersHandler(
	progress ProgressReader,
	certifications CertificationReader,
	lessons LessonReaderForHandler,
	audit *db.AuditEventStore,
	logger *zerolog.Logger,
) *UsersHandler {
	return &UsersHandler{
		ProgressStore:      progress,
		CertificationStore: certifications,
		Lessons:            lessons,
		Audit:              audit,
		Logger:             logger,
	}
}

// Progress handles GET /users/{id}/progress.
func (h *UsersHandler) Progress(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	userID, err := uuid.Parse(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "user id must be a UUID")
		return
	}

	rows, err := h.ProgressStore.GetByUser(r.Context(), userID)
	if err != nil {
		h.log().Error().Err(err).Str("user_id", id).Msg("users.progress")
		writeError(w, http.StatusInternalServerError, "internal_error", "progress lookup failed")
		return
	}

	type lessonProgress struct {
		LessonID    string  `json:"lesson_id"`
		Status      string  `json:"status"`
		Score       *int    `json:"score"`
		StartedAt   string  `json:"started_at"`
		CompletedAt *string `json:"completed_at"`
	}

	lessons := make([]lessonProgress, 0, len(rows))
	completed := 0
	inProgress := 0

	for _, p := range rows {
		lp := lessonProgress{
			LessonID:  p.LessonID.String(),
			Status:    p.Status,
			Score:     p.Score,
			StartedAt: p.StartedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}
		if p.CompletedAt != nil {
			s := p.CompletedAt.UTC().Format("2006-01-02T15:04:05Z")
			lp.CompletedAt = &s
		}

		// Optionally enrich with lesson metadata (best-effort, no 500 on miss).
		if h.Lessons != nil {
			if l, lerr := h.Lessons.Get(r.Context(), p.LessonID); lerr == nil {
				_ = l // title/slug available for future enrichment
			}
		}

		switch p.Status {
		case "completed":
			completed++
		default:
			inProgress++
		}

		lessons = append(lessons, lp)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": id,
		"tracks":  []any{},
		"lessons": lessons,
		"quizzes": []any{},
		"summary": map[string]any{
			"completed":   completed,
			"in_progress": inProgress,
		},
	})
}

// Certifications handles GET /users/{id}/certifications.
func (h *UsersHandler) Certifications(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	userID, err := uuid.Parse(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "user id must be a UUID")
		return
	}

	rows, err := h.CertificationStore.ListByUser(r.Context(), userID, false)
	if err != nil {
		h.log().Error().Err(err).Str("user_id", id).Msg("users.certifications")
		writeError(w, http.StatusInternalServerError, "internal_error", "certifications lookup failed")
		return
	}

	type certEntry struct {
		ID        string  `json:"id"`
		TrackID   string  `json:"track_id"`
		Serial    string  `json:"serial"`
		IssuedAt  string  `json:"issued_at"`
		ExpiresAt *string `json:"expires_at"`
		Revoked   bool    `json:"revoked"`
	}

	certs := make([]certEntry, 0, len(rows))
	for _, c := range rows {
		ce := certEntry{
			ID:       c.ID.String(),
			TrackID:  c.TrackID.String(),
			Serial:   c.Serial,
			IssuedAt: c.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Revoked:  c.Revoked,
		}
		if c.ExpiresAt != nil {
			s := c.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
			ce.ExpiresAt = &s
		}
		certs = append(certs, ce)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":        id,
		"certifications": certs,
	})
}

func (h *UsersHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}

// ── Stub fallbacks (v0.0.1) ───────────────────────────────────────────────────

// UserProgress returns an empty placeholder progress envelope.
func UserProgress() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		log.Info().Str("event", "users.progress").Str("user_id", id).Msg("get progress")
		writeJSON(w, http.StatusOK, map[string]any{
			"user_id":  id,
			"tracks":   []any{},
			"lessons":  []any{},
			"quizzes":  []any{},
			"summary":  map[string]any{"completed": 0, "in_progress": 0},
		})
	}
}

// UserCertifications returns an empty placeholder certifications list.
func UserCertifications() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		log.Info().Str("event", "users.certifications").Str("user_id", id).Msg("get certifications")
		writeJSON(w, http.StatusOK, map[string]any{
			"user_id":        id,
			"certifications": []any{},
		})
	}
}
