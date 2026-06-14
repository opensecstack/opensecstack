// NIS2 coverage + recommendation handlers.
//
// v0.0.1 shipped function-form stubs (Coverage()/Recommend()). v1.0.0
// adds CoverageHandler — a struct that wraps *nis2.Client so the wire
// path in cmd/server/main.go can talk to NIS2 Compass when configured.
// The bare functions are retained for back-compat: server.go falls
// back to them when opts.Coverage is nil.
//
// See docs/nis2-integration.md.
package handlers

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/opensecstack/cyberpath/internal/db"
	"github.com/opensecstack/cyberpath/internal/nis2"
)

// LessonsByTrackReader is the slice of LessonStore CoverageHandler needs
// to enumerate lessons per track when computing per-track completeness.
type LessonsByTrackReader interface {
	ListByTrack(ctx context.Context, trackID uuid.UUID) ([]db.Lesson, error)
}

// CoverageHandler wraps the NIS2 client. When the client is nil the
// handler degrades to the v0.0.1 stub responses so the server stays
// runnable in dev without NIS2 Compass configured.
//
// When Progress, Tracks and Lessons are also wired the Coverage()
// method computes a real NIS2 coverage report by cross-referencing the
// user's completed lessons against every published track's NIS2Refs.
type CoverageHandler struct {
	Client   *nis2.Client
	Logger   *zerolog.Logger
	Progress ProgressReader       // optional — from users.go
	Tracks   TrackReader          // optional — from tracks.go
	Lessons  LessonsByTrackReader // optional — for per-track lesson counts
}

// NewCoverageHandler constructs a CoverageHandler.
func NewCoverageHandler(client *nis2.Client, logger *zerolog.Logger) *CoverageHandler {
	return &CoverageHandler{Client: client, Logger: logger}
}

// WithProgress wires the optional progress and track stores used by
// Coverage() to produce a real NIS2 coverage report.
func (h *CoverageHandler) WithProgress(p ProgressReader, t TrackReader, l LessonsByTrackReader) *CoverageHandler {
	h.Progress = p
	h.Tracks = t
	h.Lessons = l
	return h
}

// coverageItem is one entry in either the coverage or gaps list.
type coverageItem struct {
	TrackID     string   `json:"track_id"`
	TrackSlug   string   `json:"track_slug"`
	NIS2Refs    []string `json:"nis2_refs"`
	PctComplete int      `json:"pct_complete"`
}

// Coverage returns the NIS2 coverage report for a user.
//
// When Progress, Tracks and Lessons are all wired it computes a live
// report; otherwise it falls back to the v0.0.1 stub.
func (h *CoverageHandler) Coverage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawID := chi.URLParam(r, "user_id")
		if h.Logger != nil {
			h.Logger.Info().Str("event", "coverage.get").Str("user_id", rawID).Msg("get coverage")
		}

		// Degrade gracefully when stores are not wired.
		if h.Progress == nil || h.Tracks == nil || h.Lessons == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"user_id":   rawID,
				"coverage":  []any{},
				"gaps":      []any{},
				"generated": "stub",
			})
			return
		}

		userID, err := uuid.Parse(rawID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_id", "user_id must be a UUID")
			return
		}

		ctx := r.Context()

		// 1. Fetch the user's progress rows and build a set of completed lesson IDs.
		progressRows, err := h.Progress.GetByUser(ctx, userID)
		if err != nil {
			h.log().Error().Err(err).Str("user_id", rawID).Msg("coverage: get progress")
			writeError(w, http.StatusInternalServerError, "internal_error", "progress lookup failed")
			return
		}
		completedLessons := make(map[uuid.UUID]struct{}, len(progressRows))
		for _, p := range progressRows {
			if p.Status == "completed" {
				completedLessons[p.LessonID] = struct{}{}
			}
		}

		// 2. List all published tracks.
		pub := true
		tracks, err := h.Tracks.List(ctx, db.TrackFilter{Published: &pub})
		if err != nil {
			h.log().Error().Err(err).Msg("coverage: list tracks")
			writeError(w, http.StatusInternalServerError, "internal_error", "track listing failed")
			return
		}

		// 3. For each track that has NIS2 references, compute completion %.
		covered := make([]coverageItem, 0)
		gaps := make([]coverageItem, 0)

		for _, t := range tracks {
			if len(t.NIS2Refs) == 0 {
				continue
			}

			lessons, err := h.Lessons.ListByTrack(ctx, t.ID)
			if err != nil {
				h.log().Warn().Err(err).Str("track_id", t.ID.String()).Msg("coverage: list lessons; skipping track")
				continue
			}

			total := len(lessons)
			if total == 0 {
				continue
			}

			done := 0
			for _, l := range lessons {
				if _, ok := completedLessons[l.ID]; ok {
					done++
				}
			}

			pct := (done * 100) / total
			item := coverageItem{
				TrackID:     t.ID.String(),
				TrackSlug:   t.Slug,
				NIS2Refs:    t.NIS2Refs,
				PctComplete: pct,
			}

			if pct == 100 {
				covered = append(covered, item)
			} else {
				gaps = append(gaps, item)
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"user_id":   rawID,
			"coverage":  covered,
			"gaps":      gaps,
			"generated": "live",
		})
	}
}

func (h *CoverageHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}

// Recommend returns a NIS2 track recommendation for a gap. When the
// NIS2 client is configured we proxy to /api/v1/recommend; otherwise
// we return an empty placeholder so dev environments stay usable.
func (h *CoverageHandler) Recommend() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gap := r.URL.Query().Get("gap")
		if h.Logger != nil {
			h.Logger.Info().Str("event", "coverage.recommend").Str("gap", gap).Msg("recommend")
		}
		if h.Client == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"gap":         gap,
				"recommended": []any{},
			})
			return
		}
		recs, err := h.Client.RecommendTracks(r.Context(), "", nis2.GapID(gap))
		if err != nil {
			if h.Logger != nil {
				h.Logger.Warn().Err(err).Str("gap", gap).Msg("nis2 recommend failed; degrading")
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"gap":         gap,
				"recommended": []any{},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"gap":         gap,
			"recommended": recs,
		})
	}
}

// Coverage is the v0.0.1 stub used when no CoverageHandler is wired.
func Coverage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := chi.URLParam(r, "user_id")
		log.Info().Str("event", "coverage.get").Str("user_id", userID).Msg("get coverage")
		writeJSON(w, http.StatusOK, map[string]any{
			"user_id":   userID,
			"coverage":  []any{},
			"gaps":      []any{},
			"generated": "stub",
		})
	}
}

// Recommend is the v0.0.1 stub used when no CoverageHandler is wired.
func Recommend() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gap := r.URL.Query().Get("gap")
		log.Info().Str("event", "coverage.recommend").Str("gap", gap).Msg("recommend")
		writeJSON(w, http.StatusOK, map[string]any{
			"gap":         gap,
			"recommended": []any{},
		})
	}
}
