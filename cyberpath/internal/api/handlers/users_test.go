// Tests for UsersHandler (users.go).
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ── fakes ─────────────────────────────────────────────────────────────────
//
// fakeProgressReader (implements ProgressReader) is already declared in
// coverage_test.go — reused here rather than redeclared.

type fakeCertificationReader struct {
	rows []db.Certification
	err  error
}

func (f *fakeCertificationReader) ListByUser(_ context.Context, _ uuid.UUID, _ bool) ([]db.Certification, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

func newUsersRequest(method, path, idParam string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", idParam)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	return req.WithContext(ctx)
}

// ── Progress ─────────────────────────────────────────────────────────────

func TestUsersHandler_Progress_InvalidID(t *testing.T) {
	h := NewUsersHandler(&fakeProgressReader{}, &fakeCertificationReader{}, nil, nil, nil)
	req := newUsersRequest(http.MethodGet, "/users/not-a-uuid/progress", "not-a-uuid")
	rec := httptest.NewRecorder()

	h.Progress(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUsersHandler_Progress_StoreError(t *testing.T) {
	h := NewUsersHandler(&fakeProgressReader{err: errors.New("db down")}, &fakeCertificationReader{}, nil, nil, nil)
	userID := uuid.New()
	req := newUsersRequest(http.MethodGet, "/users/"+userID.String()+"/progress", userID.String())
	rec := httptest.NewRecorder()

	h.Progress(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUsersHandler_Progress_Success(t *testing.T) {
	userID := uuid.New()
	lessonID1 := uuid.New()
	lessonID2 := uuid.New()
	completedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	score := 95

	h := NewUsersHandler(&fakeProgressReader{rows: []db.Progress{
		{ID: uuid.New(), UserID: userID, LessonID: lessonID1, Status: "completed", Score: &score, StartedAt: completedAt.Add(-time.Hour), CompletedAt: &completedAt},
		{ID: uuid.New(), UserID: userID, LessonID: lessonID2, Status: "in_progress", StartedAt: completedAt},
	}}, &fakeCertificationReader{}, nil, nil, nil)

	req := newUsersRequest(http.MethodGet, "/users/"+userID.String()+"/progress", userID.String())
	rec := httptest.NewRecorder()

	h.Progress(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		UserID  string `json:"user_id"`
		Lessons []struct {
			LessonID    string  `json:"lesson_id"`
			Status      string  `json:"status"`
			Score       *int    `json:"score"`
			CompletedAt *string `json:"completed_at"`
		} `json:"lessons"`
		Summary struct {
			Completed  int `json:"completed"`
			InProgress int `json:"in_progress"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.UserID != userID.String() {
		t.Fatalf("expected user_id=%s, got %s", userID, body.UserID)
	}
	if len(body.Lessons) != 2 {
		t.Fatalf("expected 2 lessons, got %d", len(body.Lessons))
	}
	// completion/in-progress counting must match status field exactly.
	if body.Summary.Completed != 1 || body.Summary.InProgress != 1 {
		t.Fatalf("expected 1 completed + 1 in_progress, got %+v", body.Summary)
	}
	if body.Lessons[0].Score == nil || *body.Lessons[0].Score != 95 {
		t.Fatalf("expected score=95 for completed lesson, got %v", body.Lessons[0].Score)
	}
	if body.Lessons[0].CompletedAt == nil {
		t.Fatalf("expected completed_at to be set for completed lesson")
	}
	if body.Lessons[1].CompletedAt != nil {
		t.Fatalf("expected completed_at to be nil for in_progress lesson")
	}
}

func TestUsersHandler_Progress_EmptyRows(t *testing.T) {
	userID := uuid.New()
	h := NewUsersHandler(&fakeProgressReader{rows: nil}, &fakeCertificationReader{}, nil, nil, nil)
	req := newUsersRequest(http.MethodGet, "/users/"+userID.String()+"/progress", userID.String())
	rec := httptest.NewRecorder()

	h.Progress(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body struct {
		Lessons []any `json:"lessons"`
		Summary struct {
			Completed  int `json:"completed"`
			InProgress int `json:"in_progress"`
		} `json:"summary"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Lessons) != 0 {
		t.Fatalf("expected empty lessons slice, got %d", len(body.Lessons))
	}
	if body.Summary.Completed != 0 || body.Summary.InProgress != 0 {
		t.Fatalf("expected zeroed summary, got %+v", body.Summary)
	}
}

// ── Certifications ───────────────────────────────────────────────────────

func TestUsersHandler_Certifications_InvalidID(t *testing.T) {
	h := NewUsersHandler(&fakeProgressReader{}, &fakeCertificationReader{}, nil, nil, nil)
	req := newUsersRequest(http.MethodGet, "/users/bad-id/certifications", "bad-id")
	rec := httptest.NewRecorder()

	h.Certifications(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUsersHandler_Certifications_StoreError(t *testing.T) {
	h := NewUsersHandler(&fakeProgressReader{}, &fakeCertificationReader{err: errors.New("db down")}, nil, nil, nil)
	userID := uuid.New()
	req := newUsersRequest(http.MethodGet, "/users/"+userID.String()+"/certifications", userID.String())
	rec := httptest.NewRecorder()

	h.Certifications(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUsersHandler_Certifications_Success(t *testing.T) {
	userID := uuid.New()
	trackID := uuid.New()
	issuedAt := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.AddDate(1, 0, 0)

	h := NewUsersHandler(&fakeProgressReader{}, &fakeCertificationReader{rows: []db.Certification{
		{ID: uuid.New(), UserID: userID, TrackID: trackID, Serial: "CP-0001", IssuedAt: issuedAt, ExpiresAt: &expiresAt, Revoked: false},
		{ID: uuid.New(), UserID: userID, TrackID: trackID, Serial: "CP-0002", IssuedAt: issuedAt, Revoked: true},
	}}, nil, nil, nil)

	req := newUsersRequest(http.MethodGet, "/users/"+userID.String()+"/certifications", userID.String())
	rec := httptest.NewRecorder()

	h.Certifications(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Certifications []struct {
			Serial    string  `json:"serial"`
			ExpiresAt *string `json:"expires_at"`
			Revoked   bool    `json:"revoked"`
		} `json:"certifications"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Certifications) != 2 {
		t.Fatalf("expected 2 certifications, got %d", len(body.Certifications))
	}
	if body.Certifications[0].ExpiresAt == nil {
		t.Fatalf("expected expires_at to be set for first cert")
	}
	if body.Certifications[1].ExpiresAt != nil {
		t.Fatalf("expected expires_at to be nil for second cert")
	}
	if !body.Certifications[1].Revoked {
		t.Fatalf("expected second cert to be revoked")
	}
}

// ── Stub fallbacks (v0.0.1) ────────────────────────────────────────────

func TestUserProgress_Stub(t *testing.T) {
	userID := uuid.New()
	req := newUsersRequest(http.MethodGet, "/users/"+userID.String()+"/progress", userID.String())
	rec := httptest.NewRecorder()

	UserProgress()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["user_id"] != userID.String() {
		t.Fatalf("expected user_id echoed, got %v", body["user_id"])
	}
}

func TestUserCertifications_Stub(t *testing.T) {
	userID := uuid.New()
	req := newUsersRequest(http.MethodGet, "/users/"+userID.String()+"/certifications", userID.String())
	rec := httptest.NewRecorder()

	UserCertifications()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["user_id"] != userID.String() {
		t.Fatalf("expected user_id echoed, got %v", body["user_id"])
	}
}
