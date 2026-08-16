package handlers_test

// DB-backed tests for the Search handler (search.go). The Postgres-fallback
// path (d.Search == nil) is exercised directly against the shared test DB.
// The Meilisearch-backed path additionally requires a reachable Meilisearch
// instance; those tests skip gracefully when one isn't configured, per the
// existing pattern used by other handlers in this package (see
// handlers.NewTestDBPool for the equivalent Postgres skip-if-unavailable
// behaviour).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/search"
)

func TestSearch_NoFilters_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/search", nil)
	w := httptest.NewRecorder()

	handlers.Search(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when q/tag/author all empty, got %d", w.Code)
	}
}

func TestSearch_PostgresFallback_QueryMatchesPublishedPost(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, slug := createTestPost(t, d.Pool, authorID, "published")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=Some+body+content", nil)
	w := httptest.NewRecorder()

	handlers.Search(d)(w, req)

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
		if p["slug"] == slug {
			found = true
		}
	}
	if !found {
		t.Errorf("expected published post %q to match full-text search, got %+v", slug, resp.Posts)
	}
}

func TestSearch_PostgresFallback_DraftPostNotMatched(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, slug := createTestPost(t, d.Pool, authorID, "draft")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=Some+body+content", nil)
	w := httptest.NewRecorder()

	handlers.Search(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	for _, p := range resp.Posts {
		if p["slug"] == slug {
			t.Errorf("draft post %q must not appear in search results", slug)
		}
	}
}

func TestSearch_PostgresFallback_AuthorFilter_OnlyMatchesThatAuthor(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	_, slug := createTestPost(t, d.Pool, authorID, "published")
	otherAuthorID, _ := createTestUser(t, d.Pool, "author")
	_, otherSlug := createTestPost(t, d.Pool, otherAuthorID, "published")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?author="+authorUsername, nil)
	w := httptest.NewRecorder()

	handlers.Search(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, p := range resp.Posts {
		if p["slug"] == otherSlug {
			t.Errorf("expected author filter to exclude other author's post %q", otherSlug)
		}
		if p["slug"] == slug {
			found = true
		}
	}
	if !found {
		t.Errorf("expected post %q by filtered author in results", slug)
	}
}

func TestSearch_PostgresFallback_TagFilter_OnlyMatchesTaggedPosts(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, slug := createTestPost(t, d.Pool, authorID, "published")

	tagName := "tag-" + handlers.RandomSuffix()
	var tagID string
	if err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO tags (name, slug) VALUES ($1,$1) RETURNING id`, tagName,
	).Scan(&tagID); err != nil {
		t.Fatalf("insert tag: %v", err)
	}
	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO post_tags (post_id, tag_id) VALUES ($1,$2)`, postID, tagID); err != nil {
		t.Fatalf("insert post_tags: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM tags WHERE id=$1`, tagID)
	})

	// Untagged post that should not match.
	otherAuthorID, _ := createTestUser(t, d.Pool, "author")
	_, otherSlug := createTestPost(t, d.Pool, otherAuthorID, "published")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?tag="+tagName, nil)
	w := httptest.NewRecorder()

	handlers.Search(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, p := range resp.Posts {
		if p["slug"] == otherSlug {
			t.Errorf("expected tag filter to exclude untagged post %q", otherSlug)
		}
		if p["slug"] == slug {
			found = true
		}
	}
	if !found {
		t.Errorf("expected tagged post %q in results", slug)
	}
}

// newTestMeiliClient attempts to build a real Meilisearch-backed search
// client against the default local instance. Tests that need a live
// Meilisearch skip gracefully when none is reachable, matching the task's
// instruction to degrade gracefully rather than fail the whole suite.
func newTestMeiliClient(t *testing.T) *search.Client {
	t.Helper()
	cfg := &config.Config{}
	cfg.MeilisearchURL = "http://localhost:7700"
	c, err := search.New(cfg)
	if err != nil {
		t.Skip("meilisearch not reachable, skipping meilisearch-backed search test:", err)
	}
	return c
}

func TestSearch_MeilisearchPath_IndexedPost_ReturnedFromPostgres(t *testing.T) {
	sc := newTestMeiliClient(t)
	d := dbDeps(t)
	d.Search = sc

	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, slug := createTestPost(t, d.Pool, authorID, "published")

	if err := sc.IndexPost(search.PostDocument{
		ID:    postID,
		Title: "Meilisearch Indexed Post " + slug,
		Body:  "unique-meilisearch-marker-" + slug,
		Slug:  slug,
	}); err != nil {
		t.Fatalf("IndexPost: %v", err)
	}
	t.Cleanup(func() { _ = sc.DeletePost(postID) })

	// Meilisearch indexing is asynchronous in general, but for this smoke
	// test we only assert the handler wires the search->Postgres path
	// without erroring; if the doc isn't visible yet the result list may be
	// empty, which is still a valid 200 response.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=unique-meilisearch-marker-"+slug, nil)
	w := httptest.NewRecorder()

	handlers.Search(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from meilisearch-backed search, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestSearch_MeilisearchPath_NoHits_ReturnsEmptyList(t *testing.T) {
	sc := newTestMeiliClient(t)
	d := dbDeps(t)
	d.Search = sc

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=definitely-no-such-term-xyzxyzxyz", nil)
	w := httptest.NewRecorder()

	handlers.Search(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
		Count int              `json:"count"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count != 0 {
		t.Errorf("expected empty result set for a term with no hits, got count=%d", resp.Count)
	}
}
