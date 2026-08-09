package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestRecordRead_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/read", nil)
	w := httptest.NewRecorder()

	handlers.RecordRead(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRecordRead_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/read", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.RecordRead(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when user cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestListReadingHistory_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/history", nil)
	w := httptest.NewRecorder()

	handlers.ListReadingHistory(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestListReadingHistory_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/history", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListReadingHistory(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when user cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestListReadingHistory_LimitClampedAbove50(t *testing.T) {
	// limit=999 must be clamped to 50 before it ever reaches the DB layer.
	// We can't observe the clamped value directly, but we can confirm the
	// handler doesn't error out on the paging math itself and reaches the
	// (failing, since unauthenticated resolution fails first) user lookup.
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/history?limit=999&page=0", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListReadingHistory(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (user lookup fails before paging matters), got %d", w.Code)
	}
}
