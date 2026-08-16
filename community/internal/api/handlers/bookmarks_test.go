package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

// --- Live-DB tests: full bookmark lifecycle + cross-user isolation ---

func TestBookmarks_FullLifecycle_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	authorID, _ := mkUser13(t, pool, "author")
	viewerID, viewerUsername := mkUser13(t, pool, "author")
	otherID, otherUsername := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", authorID, viewerID, otherID)

	postID := mkPost13(t, pool, authorID, "published")
	defer cleanup13(pool, "posts", "id", postID)

	// Status before bookmarking: false.
	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+postID+"/bookmark-status", nil)
	statusReq.SetPathValue("id", postID)
	statusReq = withClaims(statusReq, &auth.Claims{Sub: viewerUsername, Role: "author"})
	statusW := httptest.NewRecorder()
	handlers.GetBookmarkStatus(d)(statusW, statusReq)
	var statusResp map[string]bool
	_ = json.NewDecoder(statusW.Body).Decode(&statusResp)
	if statusResp["bookmarked"] {
		t.Fatalf("expected not bookmarked initially")
	}

	// Bookmark it.
	bmReq := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/bookmark", nil)
	bmReq.SetPathValue("id", postID)
	bmReq = withClaims(bmReq, &auth.Claims{Sub: viewerUsername, Role: "author"})
	bmW := httptest.NewRecorder()
	handlers.BookmarkPost(d)(bmW, bmReq)
	if bmW.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", bmW.Code, bmW.Body.String())
	}

	// Idempotent: bookmarking again does not error (ON CONFLICT DO NOTHING).
	bmW2 := httptest.NewRecorder()
	handlers.BookmarkPost(d)(bmW2, bmReq)
	if bmW2.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on duplicate bookmark, got %d", bmW2.Code)
	}

	// Status now true for viewer.
	statusW2 := httptest.NewRecorder()
	handlers.GetBookmarkStatus(d)(statusW2, statusReq)
	var statusResp2 map[string]bool
	_ = json.NewDecoder(statusW2.Body).Decode(&statusResp2)
	if !statusResp2["bookmarked"] {
		t.Fatalf("expected bookmarked=true after bookmarking")
	}

	// Isolation: a different user must not see it as bookmarked, and must not
	// see it in their own bookmark list.
	otherStatusReq := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+postID+"/bookmark-status", nil)
	otherStatusReq.SetPathValue("id", postID)
	otherStatusReq = withClaims(otherStatusReq, &auth.Claims{Sub: otherUsername, Role: "author"})
	otherStatusW := httptest.NewRecorder()
	handlers.GetBookmarkStatus(d)(otherStatusW, otherStatusReq)
	var otherStatusResp map[string]bool
	_ = json.NewDecoder(otherStatusW.Body).Decode(&otherStatusResp)
	if otherStatusResp["bookmarked"] {
		t.Errorf("expected other user's bookmark status to be false (isolation), got true")
	}

	otherListReq := httptest.NewRequest(http.MethodGet, "/api/v1/me/bookmarks", nil)
	otherListReq = withClaims(otherListReq, &auth.Claims{Sub: otherUsername, Role: "author"})
	otherListW := httptest.NewRecorder()
	handlers.ListMyBookmarks(d)(otherListW, otherListReq)
	var otherList map[string]any
	_ = json.NewDecoder(otherListW.Body).Decode(&otherList)
	if count, _ := otherList["count"].(float64); count != 0 {
		t.Errorf("expected other user to have 0 bookmarks (isolation), got %v", otherList)
	}

	// Viewer's own list contains it.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/me/bookmarks", nil)
	listReq = withClaims(listReq, &auth.Claims{Sub: viewerUsername, Role: "author"})
	listW := httptest.NewRecorder()
	handlers.ListMyBookmarks(d)(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", listW.Code, listW.Body.String())
	}
	var listResp map[string]any
	_ = json.NewDecoder(listW.Body).Decode(&listResp)
	if count, _ := listResp["count"].(float64); count != 1 {
		t.Fatalf("expected 1 bookmark in viewer's list, got %v", listResp)
	}

	// Unbookmark.
	unReq := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/"+postID+"/bookmark", nil)
	unReq.SetPathValue("id", postID)
	unReq = withClaims(unReq, &auth.Claims{Sub: viewerUsername, Role: "author"})
	unW := httptest.NewRecorder()
	handlers.UnbookmarkPost(d)(unW, unReq)
	if unW.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", unW.Code)
	}

	statusW3 := httptest.NewRecorder()
	handlers.GetBookmarkStatus(d)(statusW3, statusReq)
	var statusResp3 map[string]bool
	_ = json.NewDecoder(statusW3.Body).Decode(&statusResp3)
	if statusResp3["bookmarked"] {
		t.Errorf("expected bookmarked=false after unbookmarking")
	}
}

func TestBookmarkPost_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/bookmark", nil)
	w := httptest.NewRecorder()

	handlers.BookmarkPost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestBookmarkPost_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/bookmark", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.BookmarkPost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// UnbookmarkPost fails open: even if the user lookup fails, it must still
// report success (idempotent unbookmark), unlike BookmarkPost.
func TestUnbookmarkPost_UserNotFound_StillReturns204(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/1/bookmark", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnbookmarkPost(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 (fail-open) even when user lookup fails, got %d", w.Code)
	}
}

func TestUnbookmarkPost_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/1/bookmark", nil)
	w := httptest.NewRecorder()

	handlers.UnbookmarkPost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestListMyBookmarks_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/bookmarks", nil)
	w := httptest.NewRecorder()

	handlers.ListMyBookmarks(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestListMyBookmarks_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/bookmarks", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListMyBookmarks(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetBookmarkStatus_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/1/bookmark-status", nil)
	w := httptest.NewRecorder()

	handlers.GetBookmarkStatus(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

// GetBookmarkStatus fails open: unknown user still returns 200 bookmarked=false.
func TestGetBookmarkStatus_UserNotFound_ReturnsFalse(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/1/bookmark-status", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetBookmarkStatus(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["bookmarked"] {
		t.Error("expected bookmarked=false when user cannot be resolved")
	}
}
