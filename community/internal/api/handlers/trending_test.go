package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestListTrendingFeed_Success_ReturnsRecentPublishedPosts(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, recentSlug := createTestPost(t, d.Pool, authorID, "published")
	_, draftSlug := createTestPost(t, d.Pool, authorID, "draft")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/trending?limit=100&offset=0", nil)
	w := httptest.NewRecorder()

	handlers.ListTrendingFeed(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
		Count int              `json:"count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, p := range resp.Posts {
		if p["slug"] == recentSlug {
			found = true
			if _, ok := p["score"]; !ok {
				t.Error("expected a score field on each trending post")
			}
		}
		if p["slug"] == draftSlug {
			t.Error("draft post must not appear in trending feed")
		}
	}
	if !found {
		t.Errorf("expected recently published post %q in trending feed", recentSlug)
	}
}

func TestListTrendingFeed_ExcludesPostsOlderThan30Days(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	oldID, oldSlug := createTestPost(t, d.Pool, authorID, "published")

	if _, err := d.Pool.Exec(context.Background(),
		`UPDATE posts SET published_at = now() - INTERVAL '45 days' WHERE id=$1`, oldID); err != nil {
		t.Fatalf("backdate post: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/trending?limit=100&offset=0", nil)
	w := httptest.NewRecorder()

	handlers.ListTrendingFeed(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	for _, p := range resp.Posts {
		if p["slug"] == oldSlug {
			t.Error("post published more than 30 days ago must not appear in trending feed")
		}
	}
}

func TestListTrendingFeed_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/trending", nil)
	w := httptest.NewRecorder()

	handlers.ListTrendingFeed(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestListTrendingFeed_CustomLimitOffset_StillHitsDB(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/trending?limit=5&offset=10", nil)
	w := httptest.NewRecorder()

	handlers.ListTrendingFeed(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error with custom paging, got %d", w.Code)
	}
}
