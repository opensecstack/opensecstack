package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestGetTrendingTags_Success_ReturnsRecentTagCounts(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")

	recentTag := "trend_" + handlers.RandomSuffix()
	var recentTagID string
	if err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO tags (name, slug) VALUES ($1,$1) RETURNING id`, recentTag).Scan(&recentTagID); err != nil {
		t.Fatalf("insert recent tag: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM tags WHERE id=$1`, recentTagID) })

	oldTag := "trend_" + handlers.RandomSuffix()
	var oldTagID string
	if err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO tags (name, slug) VALUES ($1,$1) RETURNING id`, oldTag).Scan(&oldTagID); err != nil {
		t.Fatalf("insert old tag: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM tags WHERE id=$1`, oldTagID) })

	recentPostID, _ := createTestPost(t, d.Pool, authorID, "published")
	oldPostID, _ := createTestPost(t, d.Pool, authorID, "published")
	if _, err := d.Pool.Exec(context.Background(),
		`UPDATE posts SET created_at = now() - INTERVAL '30 days' WHERE id=$1`, oldPostID); err != nil {
		t.Fatalf("backdate post: %v", err)
	}

	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO post_tags (post_id, tag_id) VALUES ($1,$2)`, recentPostID, recentTagID); err != nil {
		t.Fatalf("tag recent post: %v", err)
	}
	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO post_tags (post_id, tag_id) VALUES ($1,$2)`, oldPostID, oldTagID); err != nil {
		t.Fatalf("tag old post: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM post_tags WHERE tag_id IN ($1,$2)`, recentTagID, oldTagID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/trending", nil)
	w := httptest.NewRecorder()

	handlers.GetTrendingTags(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Tags []map[string]any `json:"tags"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	foundRecent, foundOld := false, false
	for _, tg := range resp.Tags {
		if tg["name"] == recentTag {
			foundRecent = true
			if pc, _ := tg["post_count"].(float64); pc != 1 {
				t.Errorf("expected post_count=1 for recent tag, got %v", tg["post_count"])
			}
		}
		if tg["name"] == oldTag {
			foundOld = true
		}
	}
	if !foundRecent {
		t.Errorf("expected recent tag %q (used within 7 days) in trending tags", recentTag)
	}
	if foundOld {
		t.Errorf("tag %q used only by a post older than 7 days must not be trending", oldTag)
	}
}

func TestGetTrendingTags_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/trending", nil)
	w := httptest.NewRecorder()

	handlers.GetTrendingTags(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}
