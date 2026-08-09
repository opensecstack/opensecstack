package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestFollowTag_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tags/go/follow", nil)
	w := httptest.NewRecorder()

	handlers.FollowTag(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestFollowTag_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tags/go/follow", nil)
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.FollowTag(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when user cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestUnfollowTag_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tags/go/follow", nil)
	w := httptest.NewRecorder()

	handlers.UnfollowTag(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestUnfollowTag_UserNotFound_StillReturns204 verifies UnfollowTag treats
// an unresolvable user as an idempotent no-op (204) rather than an error —
// unfollowing something you were never following should not fail.
func TestUnfollowTag_UserNotFound_StillReturns204(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tags/go/follow", nil)
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnfollowTag(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestGetTagFollowStatus_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/go/follow", nil)
	w := httptest.NewRecorder()

	handlers.GetTagFollowStatus(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestGetTagFollowStatus_UserNotFound_ReturnsFalse verifies the handler
// fails closed to "following: false" rather than an error when the caller
// can't be resolved.
func TestGetTagFollowStatus_UserNotFound_ReturnsFalse(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/go/follow", nil)
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetTagFollowStatus(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]bool
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["following"] {
		t.Error("expected following=false when user cannot be resolved")
	}
}

func TestListFollowingTagsFeed_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/tags/feed", nil)
	w := httptest.NewRecorder()

	handlers.ListFollowingTagsFeed(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestListFollowingTagsFeed_UserNotFound_ReturnsEmptyList verifies the
// handler returns an empty (not error) feed when the caller can't be
// resolved, matching its degrade-gracefully design.
func TestListFollowingTagsFeed_UserNotFound_ReturnsEmptyList(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/tags/feed", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListFollowingTagsFeed(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []any `json:"posts"`
		Count int   `json:"count"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count != 0 || len(resp.Posts) != 0 {
		t.Errorf("expected empty feed, got count=%d posts=%v", resp.Count, resp.Posts)
	}
}
