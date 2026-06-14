// Integration tests for ContentVersionsHandler.
// Uses in-memory fakes — no real DB calls.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ── fake store ────────────────────────────────────────────────────────────────

// fakeContentVersionByIDGetter implements ContentVersionByIDGetter (defined in content_versions.go).
type fakeContentVersionByIDGetter struct {
	cv  *db.ContentVersion
	err error
}

func (f *fakeContentVersionByIDGetter) GetByID(_ context.Context, _ uuid.UUID) (*db.ContentVersion, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.cv, nil
}

// ── router helper ─────────────────────────────────────────────────────────────

func newContentVersionRouter(h *ContentVersionsHandler) http.Handler {
	r := chi.NewRouter()
	r.Get("/content/versions/{id}", h.Get)
	return r
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestContentVersionGet_Success(t *testing.T) {
	versionID := uuid.New()
	cv := &db.ContentVersion{
		ID:          versionID,
		EntityType:  "lesson",
		EntityID:    uuid.New().String(),
		Version:     1,
		ContentHash: "abc123",
		Payload:     json.RawMessage(`{"body":"hello"}`),
		PublishedAt: time.Now(),
	}

	h := &ContentVersionsHandler{Store: &fakeContentVersionByIDGetter{cv: cv}}
	router := newContentVersionRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/content/versions/"+versionID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Confirm it parses as valid JSON.
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
}

func TestContentVersionGet_NotFound(t *testing.T) {
	h := &ContentVersionsHandler{Store: &fakeContentVersionByIDGetter{err: pgx.ErrNoRows}}
	router := newContentVersionRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/content/versions/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != "not_found" {
		t.Errorf("code = %q, want 'not_found'", errObj["code"])
	}
}

func TestContentVersionGet_InvalidID(t *testing.T) {
	h := &ContentVersionsHandler{Store: &fakeContentVersionByIDGetter{}}
	router := newContentVersionRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/content/versions/not-a-uuid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != "invalid_id" {
		t.Errorf("code = %q, want 'invalid_id'", errObj["code"])
	}
}
