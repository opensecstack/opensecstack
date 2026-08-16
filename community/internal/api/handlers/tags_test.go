package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestListTags_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags", nil)
	w := httptest.NewRecorder()

	handlers.ListTags(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestListPostsByTag_TagAndAliasNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/nonexistent/posts", nil)
	req.SetPathValue("slug", "nonexistent")
	w := httptest.NewRecorder()

	handlers.ListPostsByTag(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when both tag and alias lookups fail, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestGetPopularTags_DBError_Returns200WithEmptyTags verifies GetPopularTags
// deliberately degrades gracefully (200 + empty list) on a query failure
// instead of a 500, since it's typically used for non-critical UI chrome.
func TestGetPopularTags_DBError_Returns200WithEmptyTags(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/popular", nil)
	w := httptest.NewRecorder()

	handlers.GetPopularTags(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even on db error, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Tags []any `json:"tags"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Tags == nil || len(resp.Tags) != 0 {
		t.Errorf("expected empty tags array, got %v", resp.Tags)
	}
}

func TestGetTag_TagAndAliasNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/nonexistent", nil)
	req.SetPathValue("slug", "nonexistent")
	w := httptest.NewRecorder()

	handlers.GetTag(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d — body: %s", w.Code, w.Body.String())
	}
}

// ---------- live-DB success-path tests ----------

func TestListTags_Success(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	slug := "tag-" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tags (name, slug) VALUES ($1,$2)`, "Tag "+slug, slug,
	); err != nil {
		t.Fatalf("insert tag: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tags WHERE slug=$1`, slug) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags?limit=100&offset=0", nil)
	w := httptest.NewRecorder()

	handlers.ListTags(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Tags []struct {
			Slug string `json:"slug"`
		} `json:"tags"`
		Count int `json:"count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, tg := range resp.Tags {
		if tg.Slug == slug {
			found = true
		}
	}
	if !found {
		t.Errorf("expected inserted tag %q to be present in listing", slug)
	}
}

func TestGetTag_Success(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	slug := "tag-" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tags (name, slug, description, color) VALUES ($1,$2,$3,$4)`,
		"Tag "+slug, slug, "a description", "#123456",
	); err != nil {
		t.Fatalf("insert tag: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tags WHERE slug=$1`, slug) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/"+slug, nil)
	req.SetPathValue("slug", slug)
	w := httptest.NewRecorder()

	handlers.GetTag(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Slug        string `json:"slug"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Slug != slug || resp.Description != "a description" {
		t.Errorf("unexpected tag payload: %+v", resp)
	}
}

func TestGetTag_AliasResolution_Success(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	slug := "tag-" + handlers.RandomSuffix()
	alias := "alias-" + handlers.RandomSuffix()

	var tagID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tags (name, slug) VALUES ($1,$2) RETURNING id`, "Tag "+slug, slug,
	).Scan(&tagID); err != nil {
		t.Fatalf("insert tag: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tags WHERE slug=$1`, slug) })

	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tag_aliases (tag_id, alias) VALUES ($1,$2)`, tagID, alias,
	); err != nil {
		t.Fatalf("insert alias: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/"+alias, nil)
	req.SetPathValue("slug", alias)
	w := httptest.NewRecorder()

	handlers.GetTag(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 resolving via alias, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Slug string `json:"slug"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Slug != slug {
		t.Errorf("expected canonical slug %q, got %q", slug, resp.Slug)
	}
}

func TestGetPopularTags_Success(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	slug := "tag-" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tags (name, slug) VALUES ($1,$2)`, "Tag "+slug, slug,
	); err != nil {
		t.Fatalf("insert tag: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tags WHERE slug=$1`, slug) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/popular", nil)
	w := httptest.NewRecorder()

	handlers.GetPopularTags(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Tags []map[string]any `json:"tags"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Tags) == 0 {
		t.Error("expected at least one popular tag")
	}
}

func TestListPostsByTag_Success_And_AliasResolution(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "tagpost_" + handlers.RandomSuffix()
	slug := "tag-" + handlers.RandomSuffix()
	alias := "alias-" + handlers.RandomSuffix()

	var authorID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username) VALUES ($1) RETURNING id`, username,
	).Scan(&authorID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	var tagID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tags (name, slug) VALUES ($1,$2) RETURNING id`, "Tag "+slug, slug,
	).Scan(&tagID); err != nil {
		t.Fatalf("insert tag: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tags WHERE slug=$1`, slug) })

	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tag_aliases (tag_id, alias) VALUES ($1,$2)`, tagID, alias,
	); err != nil {
		t.Fatalf("insert alias: %v", err)
	}

	postSlug := "post-" + handlers.RandomSuffix()
	var postID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO posts (author_id, title, slug, body, state, published_at)
		 VALUES ($1,$2,$3,'body','published', now()) RETURNING id`,
		authorID, "Test Post", postSlug,
	).Scan(&postID); err != nil {
		t.Fatalf("insert post: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO post_tags (post_id, tag_id) VALUES ($1,$2)`, postID, tagID,
	); err != nil {
		t.Fatalf("insert post_tags: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/"+slug+"/posts", nil)
	req.SetPathValue("slug", slug)
	w := httptest.NewRecorder()
	handlers.ListPostsByTag(d)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for direct slug, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count == 0 {
		t.Error("expected at least one post for the tag")
	}

	// Via alias.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/tags/"+alias+"/posts", nil)
	req2.SetPathValue("slug", alias)
	w2 := httptest.NewRecorder()
	handlers.ListPostsByTag(d)(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 for alias, got %d — body: %s", w2.Code, w2.Body.String())
	}
	var resp2 struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(w2.Body).Decode(&resp2)
	if resp2.Count == 0 {
		t.Error("expected at least one post for the tag via alias")
	}
}
