// Tests for TracksHandler (tracks.go) and the v0.0.1 stub fallbacks.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ── fakes ─────────────────────────────────────────────────────────────────

type fakeTracksByIDReader struct {
	byID   map[uuid.UUID]*db.Track
	bySlug map[string]*db.Track
	list   []db.Track
	err    error
}

func (f *fakeTracksByIDReader) Get(_ context.Context, id uuid.UUID) (*db.Track, error) {
	if f.err != nil {
		return nil, f.err
	}
	t, ok := f.byID[id]
	if !ok {
		return nil, db.ErrTrackNotFound
	}
	return t, nil
}

func (f *fakeTracksByIDReader) GetBySlug(_ context.Context, slug string) (*db.Track, error) {
	if f.err != nil {
		return nil, f.err
	}
	t, ok := f.bySlug[slug]
	if !ok {
		return nil, db.ErrTrackNotFound
	}
	return t, nil
}

func (f *fakeTracksByIDReader) List(_ context.Context, _ db.TrackFilter) ([]db.Track, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.list, nil
}

type fakeModuleReader struct {
	rows map[uuid.UUID][]db.Module
	err  error
}

func (f *fakeModuleReader) ListByTrack(_ context.Context, trackID uuid.UUID) ([]db.Module, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows[trackID], nil
}

type fakeModuleLessonsReader struct {
	rows map[uuid.UUID][]db.Lesson
	err  error
}

func (f *fakeModuleLessonsReader) ListByModule(_ context.Context, moduleID uuid.UUID) ([]db.Lesson, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows[moduleID], nil
}

func newTracksRequest(method, path, idParam string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	if idParam != "" {
		rctx.URLParams.Add("id", idParam)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	return req.WithContext(ctx)
}

// ── List ──────────────────────────────────────────────────────────────────

func TestTracksHandler_List_Success(t *testing.T) {
	trk := db.Track{ID: uuid.New(), Slug: "phishing", Title: "Phishing", Published: true}
	h := NewTracksHandler(&fakeTracksByIDReader{list: []db.Track{trk}}, &fakeModuleReader{}, &fakeModuleLessonsReader{}, nil)

	req := newTracksRequest(http.MethodGet, "/tracks", "")
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Tracks []trackSummary `json:"tracks"`
		Total  int            `json:"total"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Total != 1 || len(body.Tracks) != 1 {
		t.Fatalf("expected 1 track, got %+v", body)
	}
	if body.Tracks[0].Slug != "phishing" {
		t.Fatalf("expected slug=phishing, got %s", body.Tracks[0].Slug)
	}
}

func TestTracksHandler_List_StoreError(t *testing.T) {
	h := NewTracksHandler(&fakeTracksByIDReader{err: errors.New("db down")}, &fakeModuleReader{}, &fakeModuleLessonsReader{}, nil)
	req := newTracksRequest(http.MethodGet, "/tracks", "")
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// ── Get ───────────────────────────────────────────────────────────────────

func TestTracksHandler_Get_ByUUID(t *testing.T) {
	id := uuid.New()
	trk := db.Track{ID: id, Slug: "phishing", Title: "Phishing"}
	h := NewTracksHandler(
		&fakeTracksByIDReader{byID: map[uuid.UUID]*db.Track{id: &trk}},
		&fakeModuleReader{rows: map[uuid.UUID][]db.Module{id: {{ID: uuid.New(), Slug: "m1", Title: "Module 1", Order: 1}}}},
		&fakeModuleLessonsReader{},
		nil,
	)
	req := newTracksRequest(http.MethodGet, "/tracks/"+id.String(), id.String())
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["slug"] != "phishing" {
		t.Fatalf("expected slug=phishing, got %v", body["slug"])
	}
	mods, ok := body["modules"].([]any)
	if !ok || len(mods) != 1 {
		t.Fatalf("expected 1 module, got %v", body["modules"])
	}
}

func TestTracksHandler_Get_BySlug(t *testing.T) {
	trk := db.Track{ID: uuid.New(), Slug: "phishing", Title: "Phishing"}
	h := NewTracksHandler(
		&fakeTracksByIDReader{bySlug: map[string]*db.Track{"phishing": &trk}},
		&fakeModuleReader{},
		&fakeModuleLessonsReader{},
		nil,
	)
	req := newTracksRequest(http.MethodGet, "/tracks/phishing", "phishing")
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTracksHandler_Get_NotFound(t *testing.T) {
	h := NewTracksHandler(&fakeTracksByIDReader{}, &fakeModuleReader{}, &fakeModuleLessonsReader{}, nil)
	req := newTracksRequest(http.MethodGet, "/tracks/unknown-slug", "unknown-slug")
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTracksHandler_Get_EmptyID(t *testing.T) {
	h := NewTracksHandler(&fakeTracksByIDReader{}, &fakeModuleReader{}, &fakeModuleLessonsReader{}, nil)
	req := newTracksRequest(http.MethodGet, "/tracks/", "")
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty id, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTracksHandler_Get_ModulesStoreError(t *testing.T) {
	id := uuid.New()
	trk := db.Track{ID: id, Slug: "phishing"}
	h := NewTracksHandler(
		&fakeTracksByIDReader{byID: map[uuid.UUID]*db.Track{id: &trk}},
		&fakeModuleReader{err: errors.New("db down")},
		&fakeModuleLessonsReader{},
		nil,
	)
	req := newTracksRequest(http.MethodGet, "/tracks/"+id.String(), id.String())
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// ── ListModules ──────────────────────────────────────────────────────────

func TestTracksHandler_ListModules_WithLessons(t *testing.T) {
	trackID := uuid.New()
	modID := uuid.New()
	trk := db.Track{ID: trackID, Slug: "phishing"}
	h := NewTracksHandler(
		&fakeTracksByIDReader{byID: map[uuid.UUID]*db.Track{trackID: &trk}},
		&fakeModuleReader{rows: map[uuid.UUID][]db.Module{trackID: {{ID: modID, Slug: "m1", Title: "Module 1", Order: 1}}}},
		&fakeModuleLessonsReader{rows: map[uuid.UUID][]db.Lesson{modID: {{ID: uuid.New(), Slug: "l1", Title: "Lesson 1", Order: 1, DurationMin: 5}}}},
		nil,
	)
	req := newTracksRequest(http.MethodGet, "/tracks/"+trackID.String()+"/modules", trackID.String())
	rec := httptest.NewRecorder()
	h.ListModules(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Modules []struct {
			Lessons []lessonSummary `json:"lessons"`
		} `json:"modules"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Modules) != 1 || len(body.Modules[0].Lessons) != 1 {
		t.Fatalf("expected 1 module with 1 lesson, got %+v", body.Modules)
	}
}

// Lesson lookup errors on one module must not 500 the whole response —
// the handler falls back to an empty lesson list for that module.
func TestTracksHandler_ListModules_LessonErrorIsBestEffort(t *testing.T) {
	trackID := uuid.New()
	modID := uuid.New()
	trk := db.Track{ID: trackID, Slug: "phishing"}
	h := NewTracksHandler(
		&fakeTracksByIDReader{byID: map[uuid.UUID]*db.Track{trackID: &trk}},
		&fakeModuleReader{rows: map[uuid.UUID][]db.Module{trackID: {{ID: modID, Slug: "m1", Title: "Module 1"}}}},
		&fakeModuleLessonsReader{err: errors.New("db down")},
		nil,
	)
	req := newTracksRequest(http.MethodGet, "/tracks/"+trackID.String()+"/modules", trackID.String())
	rec := httptest.NewRecorder()
	h.ListModules(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 despite lesson store error, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Modules []struct {
			Lessons []lessonSummary `json:"lessons"`
		} `json:"modules"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Modules) != 1 || len(body.Modules[0].Lessons) != 0 {
		t.Fatalf("expected empty lessons fallback, got %+v", body.Modules)
	}
}

func TestTracksHandler_ListModules_NoLessonReader(t *testing.T) {
	trackID := uuid.New()
	modID := uuid.New()
	trk := db.Track{ID: trackID, Slug: "phishing"}
	h := NewTracksHandler(
		&fakeTracksByIDReader{byID: map[uuid.UUID]*db.Track{trackID: &trk}},
		&fakeModuleReader{rows: map[uuid.UUID][]db.Module{trackID: {{ID: modID, Slug: "m1", Title: "Module 1"}}}},
		nil, // no lesson reader wired
		nil,
	)
	req := newTracksRequest(http.MethodGet, "/tracks/"+trackID.String()+"/modules", trackID.String())
	rec := httptest.NewRecorder()
	h.ListModules(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTracksHandler_ListModules_TrackNotFound(t *testing.T) {
	h := NewTracksHandler(&fakeTracksByIDReader{}, &fakeModuleReader{}, &fakeModuleLessonsReader{}, nil)
	req := newTracksRequest(http.MethodGet, "/tracks/missing/modules", "missing")
	rec := httptest.NewRecorder()
	h.ListModules(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// ── v0.0.1 stub fallbacks ────────────────────────────────────────────────

func TestListTracks_Stub(t *testing.T) {
	req := newTracksRequest(http.MethodGet, "/tracks", "")
	rec := httptest.NewRecorder()
	ListTracks()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Total != 1 {
		t.Fatalf("expected total=1, got %d", body.Total)
	}
}

func TestGetTrack_Stub_Found(t *testing.T) {
	req := newTracksRequest(http.MethodGet, "/tracks/phishing-recognition", "phishing-recognition")
	rec := httptest.NewRecorder()
	GetTrack()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestGetTrack_Stub_NotFound(t *testing.T) {
	req := newTracksRequest(http.MethodGet, "/tracks/does-not-exist", "does-not-exist")
	rec := httptest.NewRecorder()
	GetTrack()(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestListTrackModules_Stub(t *testing.T) {
	req := newTracksRequest(http.MethodGet, "/tracks/phishing-recognition/modules", "phishing-recognition")
	rec := httptest.NewRecorder()
	ListTrackModules()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	req2 := newTracksRequest(http.MethodGet, "/tracks/nope/modules", "nope")
	rec2 := httptest.NewRecorder()
	ListTrackModules()(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec2.Code)
	}
}
