// Lesson read + completion handlers.
//
// v0.0.1 returned a hand-coded body. v1.0.0 wired LessonStore +
// ProgressStore via LessonsHandler. v0.7.0 adds Module 6 (CITADEL
// cyberpath.completion event via transactional outbox) and Module 8
// (content_version_id stamped on every completion record).
// The standalone GetLesson / CompleteLesson HandlerFuncs are retained
// as nil-safe fallbacks.
package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/opensecstack/cyberpath/internal/auth"
	"github.com/opensecstack/cyberpath/internal/db"
)

// ── v0.0.1 stub fallbacks ─────────────────────────────────────────────────────

// GetLesson returns a placeholder lesson body (v0.0.1 stub fallback).
func GetLesson() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		log.Info().Str("event", "lessons.get").Str("id", id).Msg("get lesson")
		writeJSON(w, http.StatusOK, map[string]any{
			"id":      id,
			"title":   "Sample Lesson",
			"locale":  "en",
			"body_md": "# Sample\nThis is a stub lesson.\n",
			"order":   1,
		})
	}
}

// CompleteLesson records a lesson completion (stub).
func CompleteLesson() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		log.Info().Str("event", "lessons.complete").Str("id", id).Msg("complete lesson")
		writeJSON(w, http.StatusOK, map[string]any{
			"lesson_id":     id,
			"completed":     true,
			"completion_id": "cmp_stub_" + id,
		})
	}
}

// ── DB-backed handler (v1.0.0+) ───────────────────────────────────────────────

// LessonReaderForHandler is the read slice of LessonStore the handler depends on.
type LessonReaderForHandler interface {
	Get(ctx context.Context, id uuid.UUID) (*db.Lesson, error)
}

// ProgressUpserter is the slice of ProgressStore the handler depends on.
type ProgressUpserter interface {
	Upsert(ctx context.Context, userID, lessonID uuid.UUID, status string, score *int) (*db.Progress, error)
}

// TrackForLessonReader resolves a track given a module id
// (lesson.ModuleID → module → track) for CITADEL event building.
type TrackForLessonReader interface {
	GetByModule(ctx context.Context, moduleID uuid.UUID) (*db.Track, error)
}

// ContentVersionReader returns the current (non-superseded) version for an entity.
type ContentVersionReader interface {
	GetLatest(ctx context.Context, entityType, entityID string) (*db.ContentVersion, error)
}

// CompletionCreator inserts a track/module/lesson completion record
// (Module 8: includes the content_version_id for audit reproducibility).
type CompletionCreator interface {
	Create(ctx context.Context, userID uuid.UUID, kind string, targetID uuid.UUID, score *int, correlationID string, contentVersionID *uuid.UUID) (*db.Completion, error)
}

// LessonOutboxEnqueuer enqueues an outbox entry for async CITADEL delivery.
// Uses the direct *db.OutboxStore signature to avoid needing an adapter.
type LessonOutboxEnqueuer interface {
	Enqueue(ctx context.Context, e *db.OutboxEntry) (int64, error)
}

// TrackCompletionChecker reports whether all lessons in a track are complete
// for a given user. Satisfied by *db.CompletionStore directly.
type TrackCompletionChecker interface {
	AllLessonsCompletedForTrack(ctx context.Context, userID, trackID uuid.UUID) (bool, error)
}

// CertAutoIssuer is called when a track is fully completed to trigger
// automatic certificate issuance. Satisfied by *handlers.CertificationsHandler.
type CertAutoIssuer interface {
	TryAutoIssue(ctx context.Context, userID, trackID uuid.UUID) error
}

// LessonsDeps bundles all dependencies for LessonsHandler.
// Required: Lessons, Progress. Everything else is optional — when nil
// the handler degrades gracefully (no CITADEL event / no completion record).
type LessonsDeps struct {
	Lessons  LessonReaderForHandler
	Progress ProgressUpserter
	Audit    *db.AuditEventStore
	Logger   *zerolog.Logger

	// Module 6 + 8: CITADEL event + content versioning (all optional).
	Tracks          TrackForLessonReader
	ContentVersions ContentVersionReader
	Completions     CompletionCreator
	Outbox          LessonOutboxEnqueuer
	CitadelProject  string

	// Module 5: track-level completion + auto cert issuance (all optional).
	TrackCompletion TrackCompletionChecker
	CertIssuer      CertAutoIssuer
}

// LessonsHandler serves /lessons routes from the DB.
type LessonsHandler struct {
	Lessons  LessonReaderForHandler
	Progress ProgressUpserter
	Audit    *db.AuditEventStore
	Logger   *zerolog.Logger

	// Module 6 + 8 (all optional — nil = skip).
	Tracks          TrackForLessonReader
	ContentVersions ContentVersionReader
	Completions     CompletionCreator
	Outbox          LessonOutboxEnqueuer
	CitadelProject  string

	// Module 5 (all optional — nil = skip).
	TrackCompletion TrackCompletionChecker
	CertIssuer      CertAutoIssuer
}

// NewLessonsHandler wires a LessonsHandler from a LessonsDeps bundle.
func NewLessonsHandler(deps LessonsDeps) *LessonsHandler {
	return &LessonsHandler{
		Lessons:         deps.Lessons,
		Progress:        deps.Progress,
		Audit:           deps.Audit,
		Logger:          deps.Logger,
		Tracks:          deps.Tracks,
		ContentVersions: deps.ContentVersions,
		Completions:     deps.Completions,
		Outbox:          deps.Outbox,
		CitadelProject:  deps.CitadelProject,
		TrackCompletion: deps.TrackCompletion,
		CertIssuer:      deps.CertIssuer,
	}
}

// Get handles GET /lessons/{id}.
func (h *LessonsHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	lid, err := uuid.Parse(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "lesson id must be a UUID")
		return
	}
	l, err := h.Lessons.Get(r.Context(), lid)
	if err != nil {
		if errors.Is(err, db.ErrLessonNotFound) {
			writeError(w, http.StatusNotFound, "lesson_not_found", "no lesson with id "+id)
			return
		}
		h.log().Error().Err(err).Msg("lessons.get")
		writeError(w, http.StatusInternalServerError, "internal_error", "lesson lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":           l.ID.String(),
		"module_id":    l.ModuleID.String(),
		"slug":         l.Slug,
		"title":        l.Title,
		"locale":       l.Locale,
		"body_md":      l.BodyMD,
		"order":        l.Order,
		"duration_min": l.DurationMin,
	})
}

// Complete handles POST /lessons/{id}/complete.
//
// Core flow: upsert progress row → Module 6+8 best-effort (completion record
// + CITADEL outbox event) → audit emit → 200 response.
// The CITADEL path is non-blocking: errors are logged but never fail the
// learner-visible request.
func (h *LessonsHandler) Complete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	lid, err := uuid.Parse(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "lesson id must be a UUID")
		return
	}
	uid, ok := userIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing_token", "authentication required")
		return
	}
	// Body is optional — accept {"time_spent_seconds": N} for forward compat.
	var body struct {
		TimeSpentSeconds int `json:"time_spent_seconds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	p, err := h.Progress.Upsert(r.Context(), uid, lid, "completed", nil)
	if err != nil {
		h.log().Error().Err(err).Msg("lessons.complete")
		writeError(w, http.StatusInternalServerError, "internal_error", "progress upsert failed")
		return
	}

	// Module 6 + 8: write completion record + enqueue CITADEL event.
	compID := h.recordCompletion(r.Context(), uid, lid, p)

	// Module 5: check whether the lesson was the last in its track; if so,
	// emit track-level completion event and auto-issue certificate.
	h.checkTrackCompletion(r.Context(), uid, lid)

	// Best-effort audit emit.
	if h.Audit != nil {
		uidCopy := uid
		_ = h.Audit.Append(r.Context(), &db.AuditEvent{
			ActorUserID: &uidCopy,
			Action:      "lesson.complete",
			TargetType:  "lesson",
			TargetID:    lid.String(),
			Outcome:     "success",
		})
	}

	resp := map[string]any{
		"lesson_id":    lid.String(),
		"completed":    true,
		"progress_id":  p.ID.String(),
		"status":       p.Status,
		"completed_at": p.CompletedAt,
	}
	if compID != uuid.Nil {
		resp["completion_id"] = compID.String()
	}
	writeJSON(w, http.StatusOK, resp)
}

// recordCompletion writes the completions row and enqueues a CITADEL outbox
// entry. All errors are logged but do not fail the caller's request.
// Returns the completion UUID (uuid.Nil when skipped or on error).
func (h *LessonsHandler) recordCompletion(ctx context.Context, userID, lessonID uuid.UUID, p *db.Progress) uuid.UUID {
	if h.Completions == nil || h.Outbox == nil {
		return uuid.Nil
	}

	// Resolve the lesson's current content version (Module 8, best-effort).
	var cvID *uuid.UUID
	if h.ContentVersions != nil {
		cv, err := h.ContentVersions.GetLatest(ctx, "lesson", lessonID.String())
		if err == nil {
			cvID = &cv.ID
		}
	}

	// Resolve the track via lesson → module → track (for CITADEL event fields).
	var trackSlug, trackVersion string
	var nis2Refs []string
	if h.Tracks != nil && h.Lessons != nil {
		if lesson, err := h.Lessons.Get(ctx, lessonID); err == nil {
			if track, err := h.Tracks.GetByModule(ctx, lesson.ModuleID); err == nil {
				trackSlug = track.Slug
				nis2Refs = track.NIS2Refs
				if h.ContentVersions != nil {
					if tcv, err := h.ContentVersions.GetLatest(ctx, "track", track.ID.String()); err == nil {
						trackVersion = fmt.Sprintf("0.0.%d", tcv.Version)
					}
				}
			}
		}
	}

	corrID := uuid.NewString()

	comp, err := h.Completions.Create(ctx, userID, "lesson", lessonID, p.Score, corrID, cvID)
	if err != nil {
		h.log().Warn().Err(err).Str("lesson_id", lessonID.String()).Msg("recordCompletion: create")
		return uuid.Nil
	}

	payload, err := buildCompletionPayload(comp, userID, lessonID, trackSlug, trackVersion, cvID, nis2Refs, h.CitadelProject, p.Score)
	if err != nil {
		h.log().Warn().Err(err).Str("completion_id", comp.ID.String()).Msg("recordCompletion: build payload")
		return comp.ID
	}

	if _, err := h.Outbox.Enqueue(ctx, &db.OutboxEntry{
		Destination:   "citadel",
		EventType:     "cyberpath.completion",
		Payload:       payload,
		CorrelationID: corrID,
	}); err != nil {
		h.log().Warn().Err(err).Str("completion_id", comp.ID.String()).Msg("recordCompletion: enqueue")
	}
	return comp.ID
}

// buildCompletionPayload constructs the `cyberpath.completion` CITADEL event
// payload per docs/citadel-integration.md.
//
// The canonical body (all fields except evidence_hash) is SHA-256 hashed and
// embedded as "evidence_hash": "sha256:<hex>". Ed25519 signing (Module 5)
// will replace "signed_by": "none" once certification issuance lands.
func buildCompletionPayload(
	comp *db.Completion,
	userID, lessonID uuid.UUID,
	trackSlug, trackVersion string,
	cvID *uuid.UUID,
	nis2Refs []string,
	projectID string,
	score *int,
) (json.RawMessage, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	cvIDStr := ""
	if cvID != nil {
		cvIDStr = cvID.String()
	}

	// categories = "nis2." prefix on each NIS2 ref (unless already prefixed).
	categories := make([]string, 0, len(nis2Refs))
	for _, ref := range nis2Refs {
		if len(ref) >= 4 && ref[:4] == "nis2" {
			categories = append(categories, ref)
		} else {
			categories = append(categories, "nis2."+ref)
		}
	}
	measures := nis2Refs
	if measures == nil {
		measures = []string{}
	}

	patterns := []string{"lesson:" + lessonID.String()}
	if trackSlug != "" {
		patterns = append([]string{"track:" + trackSlug}, patterns...)
	}

	// Canonical body — deterministic JSON (Go sorts map keys).
	canonical := map[string]any{
		"event_type":     "cyberpath.completion",
		"subject":        "user:" + userID.String(),
		"verdict":        "completed",
		"patterns":       patterns,
		"timestamp":      now,
		"correlation_id": comp.CorrelationID,
		"cyberpath": map[string]any{
			"completion_id":        comp.ID.String(),
			"user_id":              userID.String(),
			"track_id":             trackSlug,
			"track_version":        trackVersion,
			"content_version_id":   cvIDStr,
			"completion_timestamp": now,
			"certification_level":  "lesson",
			"nis2_measures":        measures,
			"signed_by":            "none", // Ed25519 pending Module 5
		},
	}
	if len(categories) > 0 {
		canonical["categories"] = categories
	}
	if projectID != "" {
		canonical["project_id"] = projectID
	}
	if score != nil {
		canonical["score"] = float64(*score) / 100.0
	}

	canonicalBytes, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical: %w", err)
	}

	sum := sha256.Sum256(canonicalBytes)
	canonical["evidence_hash"] = "sha256:" + hex.EncodeToString(sum[:])

	return json.Marshal(canonical)
}

// checkTrackCompletion is called after every lesson completion. When the
// completed lesson was the last one in its track it:
//  1. Creates a track-level completion record (kind="track").
//  2. Enqueues a cyberpath.completion event with certification_level="track-cert".
//  3. Calls CertIssuer.TryAutoIssue for automatic certificate issuance.
//
// All steps are best-effort; errors are logged but never surfaced to the caller.
func (h *LessonsHandler) checkTrackCompletion(ctx context.Context, userID, lessonID uuid.UUID) {
	if h.TrackCompletion == nil || h.Tracks == nil || h.Lessons == nil {
		return
	}

	lesson, err := h.Lessons.Get(ctx, lessonID)
	if err != nil {
		return
	}
	track, err := h.Tracks.GetByModule(ctx, lesson.ModuleID)
	if err != nil {
		return
	}

	done, err := h.TrackCompletion.AllLessonsCompletedForTrack(ctx, userID, track.ID)
	if err != nil || !done {
		return
	}

	// Resolve track content version.
	var cvID *uuid.UUID
	trackVersion := ""
	if h.ContentVersions != nil {
		if cv, cvErr := h.ContentVersions.GetLatest(ctx, "track", track.ID.String()); cvErr == nil {
			cvID = &cv.ID
			trackVersion = fmt.Sprintf("0.0.%d", cv.Version)
		}
	}

	corrID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339)

	// Create track-level completion record (idempotent on conflict).
	var comp *db.Completion
	if h.Completions != nil {
		comp, err = h.Completions.Create(ctx, userID, "track", track.ID, nil, corrID, cvID)
		if err != nil {
			h.log().Warn().Err(err).Str("track_id", track.ID.String()).Msg("checkTrackCompletion: create completion")
		}
	}

	// Enqueue track-level cyberpath.completion event.
	if comp != nil && h.Outbox != nil {
		cvIDStr := ""
		if cvID != nil {
			cvIDStr = cvID.String()
		}
		measures := track.NIS2Refs
		if measures == nil {
			measures = []string{}
		}
		categories := make([]string, 0, len(measures))
		for _, ref := range measures {
			if len(ref) >= 4 && ref[:4] == "nis2" {
				categories = append(categories, ref)
			} else {
				categories = append(categories, "nis2."+ref)
			}
		}
		canonical := map[string]any{
			"event_type":     "cyberpath.completion",
			"subject":        "user:" + userID.String(),
			"verdict":        "completed",
			"patterns":       []string{"track:" + track.Slug},
			"timestamp":      now,
			"correlation_id": corrID,
			"cyberpath": map[string]any{
				"completion_id":        comp.ID.String(),
				"user_id":              userID.String(),
				"track_id":             track.Slug,
				"track_version":        trackVersion,
				"content_version_id":   cvIDStr,
				"completion_timestamp": now,
				"certification_level":  "track-cert",
				"nis2_measures":        measures,
				"signed_by":            "none",
			},
		}
		if len(categories) > 0 {
			canonical["categories"] = categories
		}
		if h.CitadelProject != "" {
			canonical["project_id"] = h.CitadelProject
		}
		if canonicalBytes, merr := json.Marshal(canonical); merr == nil {
			sum := sha256.Sum256(canonicalBytes)
			canonical["evidence_hash"] = "sha256:" + hex.EncodeToString(sum[:])
			if payload, merr2 := json.Marshal(canonical); merr2 == nil {
				if _, enqErr := h.Outbox.Enqueue(ctx, &db.OutboxEntry{
					Destination:   "citadel",
					EventType:     "cyberpath.completion",
					Payload:       payload,
					CorrelationID: corrID,
				}); enqErr != nil {
					h.log().Warn().Err(enqErr).Str("track_id", track.ID.String()).Msg("checkTrackCompletion: enqueue")
				}
			}
		}
	}

	// Auto-issue certificate.
	if h.CertIssuer != nil {
		if issErr := h.CertIssuer.TryAutoIssue(ctx, userID, track.ID); issErr != nil {
			h.log().Warn().Err(issErr).Str("track_id", track.ID.String()).Msg("checkTrackCompletion: TryAutoIssue")
		}
	}
}

func (h *LessonsHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}

// userIDFromContext extracts the authenticated user UUID from the JWT claims.
func userIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	c, ok := auth.FromContext(ctx)
	if !ok || c == nil || c.Sub == "" {
		return uuid.Nil, false
	}
	u, err := uuid.Parse(c.Sub)
	if err != nil {
		return uuid.Nil, false
	}
	return u, true
}
