// NIS2 coverage + recommendation handlers.
//
// Per ADR-014, CyberPath is the PULL side of the CyberPath ↔ NIS2
// Compass integration: NIS2 Compass calls these GET endpoints, it does
// not receive pushes from CyberPath. Both Coverage() and Recommend()
// serve data CyberPath already computes for its own users — completed
// lessons (ProgressReader), published tracks and their NIS2Refs
// (TrackReader), and per-track lesson counts (LessonsByTrackReader).
//
// v0.0.1 shipped function-form stubs (Coverage()/Recommend()). v1.0.0
// adds CoverageHandler — a struct wired with the DB-backed readers so
// the wire path in cmd/server/main.go can serve live data. The bare
// functions are retained for back-compat: server.go falls back to them
// when opts.Coverage is nil.
//
// See docs/nis2-integration.md and docs/api.md "NIS2 Compass
// integration".
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/opensecstack/cyberpath/internal/db"
)

// LessonsByTrackReader is the slice of LessonStore CoverageHandler needs
// to enumerate lessons per track when computing per-track completeness.
type LessonsByTrackReader interface {
	ListByTrack(ctx context.Context, trackID uuid.UUID) ([]db.Lesson, error)
}

// CoverageHandler serves the NIS2 Compass pull-side endpoints. When
// Progress/Tracks/Lessons are nil the handler degrades to the v0.0.1
// stub responses so the server stays runnable in dev without a DB.
//
// When Progress, Tracks and Lessons are all wired, Coverage() computes
// a real NIS2 coverage report by cross-referencing the user's completed
// lessons against every published track's NIS2Refs, and Recommend()
// computes real gap-driven recommendations from the same published
// tracks. Both surface data CyberPath already owns for its own users —
// neither calls out to another platform.
type CoverageHandler struct {
	Logger   *zerolog.Logger
	Progress ProgressReader       // optional — from users.go
	Tracks   TrackReader          // optional — from tracks.go
	Lessons  LessonsByTrackReader // optional — for per-track lesson counts
}

// NewCoverageHandler constructs a CoverageHandler.
func NewCoverageHandler(logger *zerolog.Logger) *CoverageHandler {
	return &CoverageHandler{Logger: logger}
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

// validGapMeasures is the Article 21(2) allowlist NIS2 Compass gap ids
// must resolve to. Mirrors internal/content/validator.go's
// validNIS2Measures (art21.a..art21.j) — the same allowlist track
// content is validated against on import, so a gap outside this set
// can never match a real track anyway.
var validGapMeasures = map[string]struct{}{
	"art21.a": {}, "art21.b": {}, "art21.c": {}, "art21.d": {},
	"art21.e": {}, "art21.f": {}, "art21.g": {}, "art21.h": {},
	"art21.i": {}, "art21.j": {},
}

// normalizeGap accepts both the dotted ("art21.g") and underscored
// ("art21_g") forms documented in docs/api.md and internal/nis2's
// former GapID comment, and returns the canonical dotted measure id
// used in db.Track.NIS2Refs.
func normalizeGap(gap string) string {
	return strings.ReplaceAll(gap, "_", ".")
}

// recommendation is one entry in a /recommend response. Field names
// mirror docs/api.md's documented shape. audience/estimated_minutes/
// lab_required/certification are documented there too, but omitted
// here: db.Track carries no such fields today, and fabricating values
// for them would misrepresent data CyberPath doesn't actually have.
type recommendation struct {
	TrackID           string   `json:"track_id"`
	TrackSlug         string   `json:"track_slug"`
	TitleEN           string   `json:"title_en"`
	AddressesMeasures []string `json:"addresses_measures"`
	Priority          string   `json:"priority"` // primary | secondary
}

// Recommend returns tracks that address a documented NIS2 gap, drawn
// from CyberPath's own published track catalogue (TrackReader). A
// track's first NIS2Ref is its content-authored "primary" mapping
// (see internal/content/loader.go's flattenNIS2 — primary measure
// first, secondary measures follow); a match against that first entry
// is reported as priority "primary", any other match as "secondary".
func (h *CoverageHandler) Recommend() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gap := r.URL.Query().Get("gap")
		if h.Logger != nil {
			h.Logger.Info().Str("event", "coverage.recommend").Str("gap", gap).Msg("recommend")
		}

		measure := normalizeGap(gap)
		if _, ok := validGapMeasures[measure]; !ok {
			writeError(w, http.StatusBadRequest, "unknown_gap", fmt.Sprintf("unknown NIS2 gap %q", gap))
			return
		}

		// Degrade gracefully when the track store is not wired.
		if h.Tracks == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"gap":             gap,
				"measure":         measure,
				"recommendations": []any{},
			})
			return
		}

		pub := true
		tracks, err := h.Tracks.List(r.Context(), db.TrackFilter{Published: &pub})
		if err != nil {
			h.log().Error().Err(err).Msg("recommend: list tracks")
			writeError(w, http.StatusInternalServerError, "internal_error", "track listing failed")
			return
		}

		recs := make([]recommendation, 0)
		for _, t := range tracks {
			idx := indexOfMeasure(t.NIS2Refs, measure)
			if idx < 0 {
				continue
			}
			priority := "secondary"
			if idx == 0 {
				priority = "primary"
			}
			recs = append(recs, recommendation{
				TrackID:           t.ID.String(),
				TrackSlug:         t.Slug,
				TitleEN:           t.Title,
				AddressesMeasures: t.NIS2Refs,
				Priority:          priority,
			})
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"gap":             gap,
			"measure":         measure,
			"recommendations": recs,
		})
	}
}

func indexOfMeasure(refs []string, measure string) int {
	for i, ref := range refs {
		if ref == measure {
			return i
		}
	}
	return -1
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
