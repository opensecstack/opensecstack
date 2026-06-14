// Integration tests for EnrollmentHandler.
// Uses in-memory fakes — no real DB calls.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/opensecstack/cyberpath/internal/auth"
	"github.com/opensecstack/cyberpath/internal/db"
)

// ── fake store ────────────────────────────────────────────────────────────────

// fakeEnroller implements Enroller (defined in enrollments.go).
type fakeEnroller struct {
	err error
}

func (f *fakeEnroller) Enroll(_ context.Context, cohortID, userID, _ uuid.UUID) (*db.CohortEnrollment, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &db.CohortEnrollment{
		ID:         uuid.New(),
		CohortID:   cohortID,
		UserID:     userID,
		EnrolledAt: time.Now(),
	}, nil
}

// pgUniqueViolation returns a *pgconn.PgError with Code "23505" (unique_violation).
func pgUniqueViolation() error {
	return &pgconn.PgError{Code: "23505", Message: "unique_violation"}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func makeEnrollHTTPRequest(t *testing.T, body any) *http.Request {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/enrollments", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func makeEnrollHTTPRequestWithAuth(t *testing.T, body any, userID uuid.UUID) *http.Request {
	t.Helper()
	r := makeEnrollHTTPRequest(t, body)
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{Sub: userID.String(), Role: "learner"}))
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestEnroll_Success(t *testing.T) {
	h := &EnrollmentHandler{Enrollments: &fakeEnroller{}}
	userID := uuid.New()
	trackID := uuid.New()

	req := makeEnrollHTTPRequestWithAuth(t, map[string]any{"track_id": trackID.String()}, userID)
	w := httptest.NewRecorder()
	h.Enroll(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, field := range []string{"enrollment_id", "track_id", "user_id", "enrolled_at"} {
		if v, ok := resp[field]; !ok || v == "" {
			t.Errorf("field %q missing or empty in response", field)
		}
	}
}

func TestEnroll_Unauthorized(t *testing.T) {
	h := &EnrollmentHandler{Enrollments: &fakeEnroller{}}

	// No auth claims in context.
	req := makeEnrollHTTPRequest(t, map[string]any{"track_id": uuid.New().String()})
	w := httptest.NewRecorder()
	h.Enroll(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestEnroll_MissingTrackID(t *testing.T) {
	h := &EnrollmentHandler{Enrollments: &fakeEnroller{}}
	userID := uuid.New()

	req := makeEnrollHTTPRequestWithAuth(t, map[string]any{}, userID) // no track_id
	w := httptest.NewRecorder()
	h.Enroll(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != "missing_track_id" {
		t.Errorf("code = %q, want 'missing_track_id'", errObj["code"])
	}
}

func TestEnroll_InvalidTrackID(t *testing.T) {
	h := &EnrollmentHandler{Enrollments: &fakeEnroller{}}
	userID := uuid.New()

	req := makeEnrollHTTPRequestWithAuth(t, map[string]any{"track_id": "bad"}, userID)
	w := httptest.NewRecorder()
	h.Enroll(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != "invalid_track_id" {
		t.Errorf("code = %q, want 'invalid_track_id'", errObj["code"])
	}
}

func TestEnroll_Duplicate_Returns409(t *testing.T) {
	h := &EnrollmentHandler{Enrollments: &fakeEnroller{err: pgUniqueViolation()}}
	userID := uuid.New()

	req := makeEnrollHTTPRequestWithAuth(t, map[string]any{"track_id": uuid.New().String()}, userID)
	w := httptest.NewRecorder()
	h.Enroll(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != "already_enrolled" {
		t.Errorf("code = %q, want 'already_enrolled'", errObj["code"])
	}
}

func TestEnroll_StoreError(t *testing.T) {
	h := &EnrollmentHandler{Enrollments: &fakeEnroller{err: errors.New("db down")}}
	userID := uuid.New()

	req := makeEnrollHTTPRequestWithAuth(t, map[string]any{"track_id": uuid.New().String()}, userID)
	w := httptest.NewRecorder()
	h.Enroll(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}
