// Track + module listing handlers.
//
// v0.0.1 returned a single hand-coded "phishing-recognition" example so
// the client + smoke tests had something concrete to consume. v1.0.0
// wires real DB-backed reads via TracksHandler. The legacy
// ListTracks/GetTrack/ListTrackModules HandlerFuncs are still exported
// so server.go can fall back to stubs when no DB is wired.
package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/opensecstack/cyberpath/internal/db"
)

type trackSummary struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Locale      string   `json:"locale"`
	Difficulty  string   `json:"difficulty"`
	Tags        []string `json:"tags"`
	NIS2Refs    []string `json:"nis2_refs"`
	Published   bool     `json:"published"`
}

type moduleSummary struct {
	ID    string `json:"id"`
	Slug  string `json:"slug"`
	Title string `json:"title"`
	Order int    `json:"order"`
}

type lessonSummary struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	Order       int    `json:"order"`
	DurationMin int    `json:"duration_min"`
}

// ── Stub fallbacks (v0.0.1) ───────────────────────────────────────

var sampleTrack = trackSummary{
	ID:          "trk_phishing_recognition",
	Slug:        "phishing-recognition",
	Title:       "Phishing Recognition",
	Description: "Recognise phishing attempts in email, SMS, and chat.",
	Locale:      "en",
	Difficulty:  "beginner",
	Tags:        []string{"phishing", "social-engineering"},
	NIS2Refs:    []string{"art21_g"},
}

var sampleModules = []moduleSummary{
	{ID: "mod_phish_01", Slug: "email-clues", Title: "Email Clues", Order: 1},
	{ID: "mod_phish_02", Slug: "sms-vishing", Title: "SMS & Vishing", Order: 2},
}

// ListTracks returns all tracks (single hand-coded example for v0.0.1).
func ListTracks() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info().Str("event", "tracks.list").Msg("list tracks")
		writeJSON(w, http.StatusOK, map[string]any{
			"tracks": []trackSummary{sampleTrack},
			"total":  1,
		})
	}
}

// GetTrack returns one track by ID.
func GetTrack() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		log.Info().Str("event", "tracks.get").Str("id", id).Msg("get track")
		if id != sampleTrack.ID && id != sampleTrack.Slug {
			writeError(w, http.StatusNotFound, "track_not_found", "no track with id "+id)
			return
		}
		writeJSON(w, http.StatusOK, sampleTrack)
	}
}

// ListTrackModules returns the modules for a track.
func ListTrackModules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		log.Info().Str("event", "tracks.modules").Str("id", id).Msg("list modules")
		if id != sampleTrack.ID && id != sampleTrack.Slug {
			writeError(w, http.StatusNotFound, "track_not_found", "no track with id "+id)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"track_id": id,
			"modules":  sampleModules,
		})
	}
}

// ── DB-backed handler (v1.0.0) ────────────────────────────────────

// TracksHandler serves /tracks routes from the DB stores.
type TracksHandler struct {
	Tracks  TrackReader
	Modules ModuleReader
	Lessons LessonReader
	Logger  *zerolog.Logger
}

// TrackReader is the read-only slice of TrackStore TracksHandler depends on.
// Defined as an interface so handler tests can plug in a fake.
type TrackReader interface {
	Get(ctx context.Context, id uuid.UUID) (*db.Track, error)
	GetBySlug(ctx context.Context, slug string) (*db.Track, error)
	List(ctx context.Context, f db.TrackFilter) ([]db.Track, error)
}

// ModuleReader — see TrackReader.
type ModuleReader interface {
	ListByTrack(ctx context.Context, trackID uuid.UUID) ([]db.Module, error)
}

// LessonReader — see TrackReader.
type LessonReader interface {
	ListByModule(ctx context.Context, moduleID uuid.UUID) ([]db.Lesson, error)
}

// NewTracksHandler wires a TracksHandler.
func NewTracksHandler(tracks TrackReader, modules ModuleReader, lessons LessonReader, logger *zerolog.Logger) *TracksHandler {
	return &TracksHandler{Tracks: tracks, Modules: modules, Lessons: lessons, Logger: logger}
}

// List handles GET /tracks. Optional ?published=true filter.
func (h *TracksHandler) List(w http.ResponseWriter, r *http.Request) {
	f := db.TrackFilter{}
	if v := r.URL.Query().Get("published"); v == "true" {
		t := true
		f.Published = &t
	} else if v == "false" {
		fl := false
		f.Published = &fl
	}
	if loc := r.URL.Query().Get("locale"); loc != "" {
		f.Locale = loc
	}
	rows, err := h.Tracks.List(r.Context(), f)
	if err != nil {
		h.log().Error().Err(err).Msg("tracks.list")
		writeError(w, http.StatusInternalServerError, "internal_error", "list tracks failed")
		return
	}
	out := make([]trackSummary, 0, len(rows))
	for _, t := range rows {
		out = append(out, trackToSummary(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tracks": out,
		"total":  len(out),
	})
}

// Get handles GET /tracks/{id}. id may be a UUID or a slug.
func (h *TracksHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := h.lookupTrack(r, id)
	if err != nil {
		h.respondLookup(w, id, err)
		return
	}
	mods, err := h.Modules.ListByTrack(r.Context(), t.ID)
	if err != nil {
		h.log().Error().Err(err).Msg("tracks.get modules")
		writeError(w, http.StatusInternalServerError, "internal_error", "list modules failed")
		return
	}
	modOut := make([]moduleSummary, 0, len(mods))
	for _, m := range mods {
		modOut = append(modOut, moduleSummary{
			ID: m.ID.String(), Slug: m.Slug, Title: m.Title, Order: m.Order,
		})
	}
	body := map[string]any{
		"id":          t.ID.String(),
		"slug":        t.Slug,
		"title":       t.Title,
		"description": t.Description,
		"locale":      t.Locale,
		"difficulty":  t.Difficulty,
		"tags":        t.Tags,
		"nis2_refs":   t.NIS2Refs,
		"published":   t.Published,
		"modules":     modOut,
	}
	writeJSON(w, http.StatusOK, body)
}

// ListModules handles GET /tracks/{id}/modules. Includes nested lessons.
func (h *TracksHandler) ListModules(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := h.lookupTrack(r, id)
	if err != nil {
		h.respondLookup(w, id, err)
		return
	}
	mods, err := h.Modules.ListByTrack(r.Context(), t.ID)
	if err != nil {
		h.log().Error().Err(err).Msg("tracks.modules")
		writeError(w, http.StatusInternalServerError, "internal_error", "list modules failed")
		return
	}
	out := make([]map[string]any, 0, len(mods))
	for _, m := range mods {
		entry := map[string]any{
			"id":    m.ID.String(),
			"slug":  m.Slug,
			"title": m.Title,
			"order": m.Order,
		}
		if h.Lessons != nil {
			lessons, err := h.Lessons.ListByModule(r.Context(), m.ID)
			if err != nil {
				h.log().Error().Err(err).Str("module_id", m.ID.String()).Msg("tracks.modules lessons")
				// Best-effort: return empty list rather than 500 on a partial failure.
				entry["lessons"] = []lessonSummary{}
			} else {
				ls := make([]lessonSummary, 0, len(lessons))
				for _, l := range lessons {
					ls = append(ls, lessonSummary{
						ID: l.ID.String(), Slug: l.Slug, Title: l.Title,
						Order: l.Order, DurationMin: l.DurationMin,
					})
				}
				entry["lessons"] = ls
			}
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"track_id": t.ID.String(),
		"modules":  out,
	})
}

// ── helpers ───────────────────────────────────────────────────────

func (h *TracksHandler) lookupTrack(r *http.Request, id string) (*db.Track, error) {
	if u, err := uuid.Parse(id); err == nil {
		return h.Tracks.Get(r.Context(), u)
	}
	if id == "" {
		return nil, errBadID
	}
	// Treat as slug. We still need to flag obviously bad UUID-looking but
	// non-parseable ids — heuristic: if it looks like a UUID prefix (has
	// hyphens at the right offsets), reject. Otherwise let the DB miss
	// resolve to ErrTrackNotFound.
	return h.Tracks.GetBySlug(r.Context(), id)
}

func (h *TracksHandler) respondLookup(w http.ResponseWriter, id string, err error) {
	if errors.Is(err, errBadID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "track id required")
		return
	}
	if errors.Is(err, db.ErrTrackNotFound) {
		writeError(w, http.StatusNotFound, "track_not_found", "no track with id "+id)
		return
	}
	h.log().Error().Err(err).Str("id", id).Msg("tracks.lookup")
	writeError(w, http.StatusInternalServerError, "internal_error", "track lookup failed")
}

func (h *TracksHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}

var errBadID = errors.New("handlers: invalid id")

func trackToSummary(t db.Track) trackSummary {
	return trackSummary{
		ID:          t.ID.String(),
		Slug:        t.Slug,
		Title:       t.Title,
		Description: t.Description,
		Locale:      t.Locale,
		Difficulty:  t.Difficulty,
		Tags:        t.Tags,
		NIS2Refs:    t.NIS2Refs,
		Published:   t.Published,
	}
}
