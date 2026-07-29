// Integration tests for CoverageHandler (Coverage + Recommend).
// Uses in-memory fakes — no real DB or NIS2 network calls.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ── fake stores ───────────────────────────────────────────────────────────────

// fakeProgressReader implements ProgressReader (defined in users.go).
type fakeProgressReader struct {
	rows []db.Progress
	err  error
}

func (f *fakeProgressReader) GetByUser(_ context.Context, _ uuid.UUID) ([]db.Progress, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

// fakeTrackReader implements TrackReader (defined in tracks.go).
type fakeTrackReader struct {
	tracks []db.Track
	err    error
}

func (f *fakeTrackReader) Get(_ context.Context, _ uuid.UUID) (*db.Track, error) {
	if len(f.tracks) > 0 {
		return &f.tracks[0], nil
	}
	return nil, db.ErrTrackNotFound
}

func (f *fakeTrackReader) GetBySlug(_ context.Context, _ string) (*db.Track, error) {
	if len(f.tracks) > 0 {
		return &f.tracks[0], nil
	}
	return nil, db.ErrTrackNotFound
}

func (f *fakeTrackReader) List(_ context.Context, _ db.TrackFilter) ([]db.Track, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tracks, nil
}

// fakeLessonsByTrackReader implements LessonsByTrackReader (defined in coverage.go).
type fakeLessonsByTrackReader struct {
	// lessonsByTrack maps trackID string -> lessons
	lessonsByTrack map[string][]db.Lesson
	err            error
}

func (f *fakeLessonsByTrackReader) ListByTrack(_ context.Context, trackID uuid.UUID) ([]db.Lesson, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.lessonsByTrack == nil {
		return nil, nil
	}
	return f.lessonsByTrack[trackID.String()], nil
}

// ── router helper ─────────────────────────────────────────────────────────────

func newCoverageRouter(h *CoverageHandler) http.Handler {
	r := chi.NewRouter()
	r.Get("/coverage/{user_id}", h.Coverage())
	r.Get("/recommend", h.Recommend())
	return r
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestCoverageHandler_NoStores_ReturnsStub(t *testing.T) {
	// Progress=nil → must degrade to stub.
	h := &CoverageHandler{
		Progress: nil,
		Tracks:   nil,
		Lessons:  nil,
	}
	router := newCoverageRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/coverage/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["generated"] != "stub" {
		t.Errorf("generated = %q, want 'stub'", resp["generated"])
	}
	if _, ok := resp["coverage"]; !ok {
		t.Errorf("missing 'coverage' field")
	}
	if _, ok := resp["gaps"]; !ok {
		t.Errorf("missing 'gaps' field")
	}
}

func TestCoverageHandler_InvalidUserID(t *testing.T) {
	h := &CoverageHandler{
		Progress: &fakeProgressReader{},
		Tracks:   &fakeTrackReader{},
		Lessons:  &fakeLessonsByTrackReader{},
	}
	router := newCoverageRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/coverage/not-a-uuid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
}

func TestCoverageHandler_AllCompleted(t *testing.T) {
	trackID := uuid.New()
	lessonA := uuid.New()
	lessonB := uuid.New()
	userID := uuid.New()

	track := db.Track{
		ID:       trackID,
		Slug:     "nis2-basics",
		NIS2Refs: []string{"art21_a", "art21_b"},
	}
	lessons := []db.Lesson{
		{ID: lessonA},
		{ID: lessonB},
	}
	progress := []db.Progress{
		{ID: uuid.New(), UserID: userID, LessonID: lessonA, Status: "completed"},
		{ID: uuid.New(), UserID: userID, LessonID: lessonB, Status: "completed"},
	}

	h := &CoverageHandler{
		Progress: &fakeProgressReader{rows: progress},
		Tracks:   &fakeTrackReader{tracks: []db.Track{track}},
		Lessons: &fakeLessonsByTrackReader{
			lessonsByTrack: map[string][]db.Lesson{
				trackID.String(): lessons,
			},
		},
	}
	router := newCoverageRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/coverage/"+userID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["generated"] != "live" {
		t.Errorf("generated = %q, want 'live'", resp["generated"])
	}

	coverage, _ := resp["coverage"].([]any)
	if len(coverage) == 0 {
		t.Errorf("coverage is empty — expected track at 100%%")
	}

	gaps, _ := resp["gaps"].([]any)
	if len(gaps) != 0 {
		t.Errorf("gaps = %d, want 0", len(gaps))
	}

	// Verify pct_complete = 100 for the coverage item.
	if len(coverage) > 0 {
		item, _ := coverage[0].(map[string]any)
		pct, _ := item["pct_complete"].(float64)
		if int(pct) != 100 {
			t.Errorf("pct_complete = %v, want 100", pct)
		}
	}
}

func TestCoverageHandler_NoneCompleted(t *testing.T) {
	trackID := uuid.New()
	lessonA := uuid.New()
	lessonB := uuid.New()
	userID := uuid.New()

	track := db.Track{
		ID:       trackID,
		Slug:     "nis2-basics",
		NIS2Refs: []string{"art21_a"},
	}
	lessons := []db.Lesson{
		{ID: lessonA},
		{ID: lessonB},
	}

	h := &CoverageHandler{
		Progress: &fakeProgressReader{rows: []db.Progress{}}, // no completions
		Tracks:   &fakeTrackReader{tracks: []db.Track{track}},
		Lessons: &fakeLessonsByTrackReader{
			lessonsByTrack: map[string][]db.Lesson{
				trackID.String(): lessons,
			},
		},
	}
	router := newCoverageRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/coverage/"+userID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	coverage, _ := resp["coverage"].([]any)
	if len(coverage) != 0 {
		t.Errorf("coverage = %d, want 0 (nothing completed)", len(coverage))
	}

	gaps, _ := resp["gaps"].([]any)
	if len(gaps) == 0 {
		t.Errorf("gaps is empty — expected track at 0%%")
	}

	if len(gaps) > 0 {
		item, _ := gaps[0].(map[string]any)
		pct, _ := item["pct_complete"].(float64)
		if int(pct) != 0 {
			t.Errorf("pct_complete = %v, want 0", pct)
		}
	}
}

func TestCoverageHandler_PartialCompletion(t *testing.T) {
	trackID := uuid.New()
	lessonA := uuid.New()
	lessonB := uuid.New()
	userID := uuid.New()

	track := db.Track{
		ID:       trackID,
		Slug:     "nis2-basics",
		NIS2Refs: []string{"art21_a"},
	}
	lessons := []db.Lesson{
		{ID: lessonA},
		{ID: lessonB},
	}
	// Only lessonA completed → 50%.
	progress := []db.Progress{
		{ID: uuid.New(), UserID: userID, LessonID: lessonA, Status: "completed"},
	}

	h := &CoverageHandler{
		Progress: &fakeProgressReader{rows: progress},
		Tracks:   &fakeTrackReader{tracks: []db.Track{track}},
		Lessons: &fakeLessonsByTrackReader{
			lessonsByTrack: map[string][]db.Lesson{
				trackID.String(): lessons,
			},
		},
	}
	router := newCoverageRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/coverage/"+userID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// 50% → goes into gaps, not coverage.
	gaps, _ := resp["gaps"].([]any)
	if len(gaps) == 0 {
		t.Fatalf("gaps is empty — expected partial track")
	}

	item, _ := gaps[0].(map[string]any)
	pct, _ := item["pct_complete"].(float64)
	if int(pct) != 50 {
		t.Errorf("pct_complete = %v, want 50", pct)
	}
}

func TestCoverageHandler_NoNIS2Refs_Skipped(t *testing.T) {
	trackID := uuid.New()
	lessonA := uuid.New()
	userID := uuid.New()

	// Track has NO NIS2 refs — must be skipped entirely.
	track := db.Track{
		ID:       trackID,
		Slug:     "no-nis2",
		NIS2Refs: []string{},
	}
	lessons := []db.Lesson{{ID: lessonA}}
	progress := []db.Progress{
		{ID: uuid.New(), UserID: userID, LessonID: lessonA, Status: "completed"},
	}

	h := &CoverageHandler{
		Progress: &fakeProgressReader{rows: progress},
		Tracks:   &fakeTrackReader{tracks: []db.Track{track}},
		Lessons: &fakeLessonsByTrackReader{
			lessonsByTrack: map[string][]db.Lesson{
				trackID.String(): lessons,
			},
		},
	}
	router := newCoverageRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/coverage/"+userID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	coverage, _ := resp["coverage"].([]any)
	gaps, _ := resp["gaps"].([]any)

	if len(coverage) != 0 || len(gaps) != 0 {
		t.Errorf("track with no NIS2 refs must not appear in coverage or gaps; coverage=%d gaps=%d", len(coverage), len(gaps))
	}
}

func TestRecommend_NoTracks_ReturnsEmpty(t *testing.T) {
	// Tracks=nil → must degrade to an empty recommendations list rather
	// than 500, so dev environments without a DB stay usable.
	h := &CoverageHandler{Tracks: nil}
	router := newCoverageRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/recommend?gap=art21_a", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["measure"] != "art21.a" {
		t.Errorf("measure = %v, want art21.a", resp["measure"])
	}
	recs, ok := resp["recommendations"].([]any)
	if !ok {
		t.Fatalf("missing 'recommendations' field")
	}
	if len(recs) != 0 {
		t.Errorf("recommendations = %v, want empty list", recs)
	}
}

func TestRecommend_UnknownGap_Returns400(t *testing.T) {
	h := &CoverageHandler{Tracks: &fakeTrackReader{}}
	router := newCoverageRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/recommend?gap=not_a_measure", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
}

func TestRecommend_MatchesPublishedTracks(t *testing.T) {
	primaryTrack := db.Track{
		ID:       uuid.New(),
		Slug:     "nis2-art21-awareness",
		Title:    "NIS2 Article 21 awareness",
		NIS2Refs: []string{"art21.g", "art21.a", "art21.b"}, // art21.g is primary (index 0)
	}
	secondaryTrack := db.Track{
		ID:       uuid.New(),
		Slug:     "incident-response-basics",
		Title:    "Incident Response Basics",
		NIS2Refs: []string{"art21.b", "art21.g"}, // art21.g is secondary here (index 1)
	}
	unrelatedTrack := db.Track{
		ID:       uuid.New(),
		Slug:     "phishing-recognition",
		Title:    "Phishing Recognition",
		NIS2Refs: []string{"art21.a"},
	}

	h := &CoverageHandler{
		Tracks: &fakeTrackReader{tracks: []db.Track{primaryTrack, secondaryTrack, unrelatedTrack}},
	}
	router := newCoverageRouter(h)

	// Accepts the underscored form and normalizes it to dotted.
	req := httptest.NewRequest(http.MethodGet, "/recommend?gap=art21_g", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["gap"] != "art21_g" {
		t.Errorf("gap = %v, want art21_g (echoed as received)", resp["gap"])
	}
	if resp["measure"] != "art21.g" {
		t.Errorf("measure = %v, want art21.g", resp["measure"])
	}

	recs, ok := resp["recommendations"].([]any)
	if !ok || len(recs) != 2 {
		t.Fatalf("recommendations = %v, want 2 entries", resp["recommendations"])
	}

	bySlug := map[string]map[string]any{}
	for _, r := range recs {
		item := r.(map[string]any)
		bySlug[item["track_slug"].(string)] = item
	}

	primary, ok := bySlug["nis2-art21-awareness"]
	if !ok {
		t.Fatalf("missing primary track in recommendations: %v", recs)
	}
	if primary["priority"] != "primary" {
		t.Errorf("primary track priority = %v, want primary", primary["priority"])
	}

	secondary, ok := bySlug["incident-response-basics"]
	if !ok {
		t.Fatalf("missing secondary track in recommendations: %v", recs)
	}
	if secondary["priority"] != "secondary" {
		t.Errorf("secondary track priority = %v, want secondary", secondary["priority"])
	}

	if _, ok := bySlug["phishing-recognition"]; ok {
		t.Errorf("unrelated track must not be recommended for art21.g: %v", recs)
	}
}
