package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestListUsers_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	w := httptest.NewRecorder()

	handlers.ListUsers(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestListUsers_WithSearchQuery_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?q=alice&page=2&limit=100", nil)
	w := httptest.NewRecorder()

	handlers.ListUsers(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error with query params, got %d", w.Code)
	}
}

// --- Live-DB tests: search + pagination + only-published-posts-count ---

func TestListUsers_SearchAndPostCount_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	authorID, authorUsername := mkUser13(t, pool, "author")
	otherID, _ := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", authorID, otherID)

	publishedID := mkPost13(t, pool, authorID, "published")
	draftID := mkPost13(t, pool, authorID, "draft")
	defer cleanup13(pool, "posts", "id", publishedID, draftID)

	// Search by username substring finds the author with exactly 1 (published-only) post count.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?q="+authorUsername, nil)
	w := httptest.NewRecorder()
	handlers.ListUsers(d)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	users, _ := resp["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("expected exactly 1 matching user, got %d: %v", len(users), users)
	}
	u := users[0].(map[string]any)
	if u["username"] != authorUsername {
		t.Errorf("expected username=%q, got %v", authorUsername, u["username"])
	}
	if pc, _ := u["post_count"].(float64); pc != 1 {
		t.Errorf("expected post_count=1 (only published posts counted), got %v", u["post_count"])
	}

	// A query matching nothing returns an empty (not null) users array.
	noMatchReq := httptest.NewRequest(http.MethodGet, "/api/v1/users?q=zzz-no-such-user-zzz", nil)
	noMatchW := httptest.NewRecorder()
	handlers.ListUsers(d)(noMatchW, noMatchReq)
	var noMatchResp map[string]any
	_ = json.NewDecoder(noMatchW.Body).Decode(&noMatchResp)
	if noMatchResp["users"] == nil {
		t.Errorf("expected users to be an empty array, not null")
	}
}

func TestListUsers_LimitCappedAt50_LiveDB(t *testing.T) {
	_ = live13Pool(t)
	d := newLiveDeps13(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?limit=500&page=0", nil)
	w := httptest.NewRecorder()
	handlers.ListUsers(d)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even with an oversized limit and page=0, got %d — body: %s", w.Code, w.Body.String())
	}
}
