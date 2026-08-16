// Integration tests for LessonsHandler.
// White-box style: same package as the handlers under test.
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ── fake stores ───────────────────────────────────────────────────────────────

// fakeLessonReader implements LessonReaderForHandler.
type fakeLessonReader struct {
	lesson *db.Lesson
	err    error
}

func (r *fakeLessonReader) Get(_ context.Context, id uuid.UUID) (*db.Lesson, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.lesson != nil {
		return r.lesson, nil
	}
	moduleID := uuid.New()
	return &db.Lesson{
		ID:          id,
		ModuleID:    moduleID,
		Slug:        "test-lesson",
		Title:       "Test Lesson",
		Locale:      "en",
		BodyMD:      "# Test\nContent here.",
		Order:       1,
		DurationMin: 10,
	}, nil
}

// fakeProgressUpserter implements ProgressUpserter.
type fakeProgressUpserter struct {
	progress *db.Progress
	err      error
}

func (p *fakeProgressUpserter) Upsert(_ context.Context, userID, lessonID uuid.UUID, status string, score *int) (*db.Progress, error) {
	if p.err != nil {
		return nil, p.err
	}
	if p.progress != nil {
		return p.progress, nil
	}
	now := time.Now()
	return &db.Progress{
		ID:          uuid.New(),
		UserID:      userID,
		LessonID:    lessonID,
		Status:      status,
		CompletedAt: &now,
	}, nil
}

// fakeTrackForLessonReader implements TrackForLessonReader.
type fakeTrackForLessonReader struct {
	track *db.Track
	err   error
}

func (r *fakeTrackForLessonReader) GetByModule(_ context.Context, moduleID uuid.UUID) (*db.Track, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.track != nil {
		return r.track, nil
	}
	return &db.Track{
		ID:   uuid.New(),
		Slug: "test-track",
	}, nil
}

// fakeCompletionCreator implements CompletionCreator.
type fakeCompletionCreator struct {
	completion *db.Completion
	err        error
}

func (c *fakeCompletionCreator) Create(_ context.Context, userID uuid.UUID, kind string, targetID uuid.UUID, score *int, correlationID string, contentVersionID *uuid.UUID) (*db.Completion, error) {
	if c.err != nil {
		return nil, c.err
	}
	if c.completion != nil {
		return c.completion, nil
	}
	return &db.Completion{
		ID:            uuid.New(),
		UserID:        userID,
		Kind:          kind,
		TargetID:      targetID,
		CorrelationID: correlationID,
		CompletedAt:   time.Now(),
	}, nil
}

// fakeLessonOutbox implements LessonOutboxEnqueuer.
type fakeLessonOutbox struct {
	mu      sync.Mutex
	entries []*db.OutboxEntry
	err     error
}

func (o *fakeLessonOutbox) Enqueue(_ context.Context, e *db.OutboxEntry) (int64, error) {
	if o.err != nil {
		return 0, o.err
	}
	o.mu.Lock()
	o.entries = append(o.entries, e)
	o.mu.Unlock()
	return 1, nil
}

func (o *fakeLessonOutbox) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.entries)
}

// fakeTrackCompletionChecker implements TrackCompletionChecker.
type fakeTrackCompletionChecker struct {
	done bool
	err  error
}

func (c *fakeTrackCompletionChecker) AllLessonsCompletedForTrack(_ context.Context, _, _ uuid.UUID) (bool, error) {
	return c.done, c.err
}

// fakeCertAutoIssuer implements CertAutoIssuer.
type fakeCertAutoIssuer struct {
	mu    sync.Mutex
	calls []struct{ userID, trackID uuid.UUID }
	err   error
}

func (i *fakeCertAutoIssuer) TryAutoIssue(_ context.Context, userID, trackID uuid.UUID) error {
	i.mu.Lock()
	i.calls = append(i.calls, struct{ userID, trackID uuid.UUID }{userID, trackID})
	i.mu.Unlock()
	return i.err
}

func (i *fakeCertAutoIssuer) callCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.calls)
}

// ── helper: lessons handler with minimum required deps ────────────────────────

func newTestLessonsHandler(lessons LessonReaderForHandler, progress ProgressUpserter) *LessonsHandler {
	return &LessonsHandler{
		Lessons:  lessons,
		Progress: progress,
	}
}

// ── Get tests ─────────────────────────────────────────────────────────────────

func TestLessonsGet_Success(t *testing.T) {
	lessonID := uuid.New()
	reader := &fakeLessonReader{}
	h := newTestLessonsHandler(reader, &fakeProgressUpserter{})

	r := chi.NewRouter()
	r.Get("/lessons/{id}", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/lessons/"+lessonID.String(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["id"] == nil || body["id"] == "" {
		t.Errorf("missing 'id' in response: %v", body)
	}
	if body["body_md"] == nil {
		t.Errorf("missing 'body_md' in response: %v", body)
	}
}

func TestLessonsGet_NotFound(t *testing.T) {
	reader := &fakeLessonReader{err: db.ErrLessonNotFound}
	h := newTestLessonsHandler(reader, &fakeProgressUpserter{})

	r := chi.NewRouter()
	r.Get("/lessons/{id}", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/lessons/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

func TestLessonsGet_InvalidID(t *testing.T) {
	reader := &fakeLessonReader{}
	h := newTestLessonsHandler(reader, &fakeProgressUpserter{})

	r := chi.NewRouter()
	r.Get("/lessons/{id}", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/lessons/not-a-uuid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

// ── Complete tests ────────────────────────────────────────────────────────────

func TestLessonsComplete_Success(t *testing.T) {
	lessonID := uuid.New()
	userID := uuid.New()
	reader := &fakeLessonReader{}
	progress := &fakeProgressUpserter{}
	h := newTestLessonsHandler(reader, progress)

	r := chi.NewRouter()
	r.Post("/lessons/{id}/complete", h.Complete)

	req := withUserCtx(
		httptest.NewRequest(http.MethodPost, "/lessons/"+lessonID.String()+"/complete",
			strings.NewReader(`{}`)),
		userID,
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["completed"] != true {
		t.Errorf("completed = %v, want true", body["completed"])
	}
	if body["progress_id"] == nil || body["progress_id"] == "" {
		t.Errorf("missing 'progress_id' in response: %v", body)
	}
}

func TestLessonsComplete_Unauthorized(t *testing.T) {
	lessonID := uuid.New()
	h := newTestLessonsHandler(&fakeLessonReader{}, &fakeProgressUpserter{})

	r := chi.NewRouter()
	r.Post("/lessons/{id}/complete", h.Complete)

	// No user context.
	req := httptest.NewRequest(http.MethodPost, "/lessons/"+lessonID.String()+"/complete", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", w.Code, w.Body.String())
	}
}

func TestLessonsComplete_InvalidID(t *testing.T) {
	userID := uuid.New()
	h := newTestLessonsHandler(&fakeLessonReader{}, &fakeProgressUpserter{})

	r := chi.NewRouter()
	r.Post("/lessons/{id}/complete", h.Complete)

	req := withUserCtx(
		httptest.NewRequest(http.MethodPost, "/lessons/not-a-uuid/complete", nil),
		userID,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestLessonsComplete_ProgressError(t *testing.T) {
	lessonID := uuid.New()
	userID := uuid.New()
	progress := &fakeProgressUpserter{err: fmt.Errorf("db unavailable")}
	h := newTestLessonsHandler(&fakeLessonReader{}, progress)

	r := chi.NewRouter()
	r.Post("/lessons/{id}/complete", h.Complete)

	req := withUserCtx(
		httptest.NewRequest(http.MethodPost, "/lessons/"+lessonID.String()+"/complete",
			strings.NewReader(`{}`)),
		userID,
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

func TestLessonsComplete_WithCompletionAndOutbox(t *testing.T) {
	lessonID := uuid.New()
	userID := uuid.New()
	moduleID := uuid.New()

	// Wire lesson with a known moduleID so the track lookup works.
	lesson := &db.Lesson{
		ID:       lessonID,
		ModuleID: moduleID,
		Slug:     "wired-lesson",
		Title:    "Wired Lesson",
		Locale:   "en",
		BodyMD:   "# Wired",
		Order:    1,
	}
	outbox := &fakeLessonOutbox{}
	h := &LessonsHandler{
		Lessons:     &fakeLessonReader{lesson: lesson},
		Progress:    &fakeProgressUpserter{},
		Completions: &fakeCompletionCreator{},
		Outbox:      outbox,
		Tracks:      &fakeTrackForLessonReader{},
	}

	r := chi.NewRouter()
	r.Post("/lessons/{id}/complete", h.Complete)

	req := withUserCtx(
		httptest.NewRequest(http.MethodPost, "/lessons/"+lessonID.String()+"/complete",
			strings.NewReader(`{}`)),
		userID,
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// At least one outbox entry for the lesson-level event.
	if outbox.count() == 0 {
		t.Errorf("expected outbox.Enqueue to have been called at least once")
	}
}

func TestLessonsComplete_TrackComplete_AutoIssueCert(t *testing.T) {
	lessonID := uuid.New()
	userID := uuid.New()
	moduleID := uuid.New()
	trackID := uuid.New()

	lesson := &db.Lesson{
		ID:       lessonID,
		ModuleID: moduleID,
		Slug:     "final-lesson",
		Title:    "Final Lesson",
		Locale:   "en",
		BodyMD:   "# Final",
		Order:    5,
	}
	track := &db.Track{
		ID:   trackID,
		Slug: "complete-track",
	}
	certIssuer := &fakeCertAutoIssuer{}
	outbox := &fakeLessonOutbox{}
	h := &LessonsHandler{
		Lessons:         &fakeLessonReader{lesson: lesson},
		Progress:        &fakeProgressUpserter{},
		Completions:     &fakeCompletionCreator{},
		Outbox:          outbox,
		Tracks:          &fakeTrackForLessonReader{track: track},
		TrackCompletion: &fakeTrackCompletionChecker{done: true},
		CertIssuer:      certIssuer,
	}

	r := chi.NewRouter()
	r.Post("/lessons/{id}/complete", h.Complete)

	req := withUserCtx(
		httptest.NewRequest(http.MethodPost, "/lessons/"+lessonID.String()+"/complete",
			strings.NewReader(`{}`)),
		userID,
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// TryAutoIssue must have been called.
	if certIssuer.callCount() == 0 {
		t.Errorf("TryAutoIssue was not called after track completion")
	}
	// Verify the correct trackID was passed.
	certIssuer.mu.Lock()
	gotTrackID := certIssuer.calls[0].trackID
	certIssuer.mu.Unlock()
	if gotTrackID != trackID {
		t.Errorf("TryAutoIssue called with trackID=%s, want %s", gotTrackID, trackID)
	}
}
