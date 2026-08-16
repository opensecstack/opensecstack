package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestGetScheduledPosts_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/scheduled-posts", nil)
	w := httptest.NewRecorder()

	handlers.GetScheduledPosts(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestGetScheduledPosts_UnknownUser_ReturnsEmpty(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/scheduled-posts", nil)
	req = withClaims(req, &auth.Claims{Sub: "nobody", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetScheduledPosts(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with empty result when user unresolvable, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if total, _ := resp["total"].(float64); total != 0 {
		t.Errorf("expected total=0, got %v", resp["total"])
	}
}

// --- Live-DB tests: success path + isolation ---

func TestGetScheduledPosts_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	authorID, authorUsername := mkUser13(t, pool, "author")
	otherID, otherUsername := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", authorID, otherID)

	scheduledID := mkPost13(t, pool, authorID, "scheduled")
	publishedID := mkPost13(t, pool, authorID, "published")
	defer cleanup13(pool, "posts", "id", scheduledID, publishedID)

	// scheduled_at must be non-null: GetScheduledPosts scans it into a
	// non-pointer string field, so a NULL value would surface as a scan error.
	if _, err := pool.Exec(context.Background(),
		`UPDATE posts SET scheduled_at = now() + interval '1 day' WHERE id = $1`, scheduledID); err != nil {
		t.Fatalf("set scheduled_at: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/scheduled-posts", nil)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()
	handlers.GetScheduledPosts(d)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	posts, _ := resp["posts"].([]any)
	if len(posts) != 1 {
		t.Fatalf("expected exactly 1 scheduled post (published post excluded), got %d: %v", len(posts), posts)
	}
	if total, _ := resp["total"].(float64); total != 1 {
		t.Errorf("expected total=1, got %v", resp["total"])
	}

	// A different author sees no scheduled posts (isolation).
	otherReq := httptest.NewRequest(http.MethodGet, "/api/v1/me/scheduled-posts", nil)
	otherReq = withClaims(otherReq, &auth.Claims{Sub: otherUsername, Role: "author"})
	otherW := httptest.NewRecorder()
	handlers.GetScheduledPosts(d)(otherW, otherReq)
	var otherResp map[string]any
	_ = json.NewDecoder(otherW.Body).Decode(&otherResp)
	otherPosts, _ := otherResp["posts"].([]any)
	if len(otherPosts) != 0 {
		t.Errorf("expected other author to see 0 scheduled posts (isolation), got %v", otherPosts)
	}
}
