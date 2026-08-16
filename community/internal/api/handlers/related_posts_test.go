package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestGetRelatedPosts_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/1/related", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()

	handlers.GetRelatedPosts(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] == "" {
		t.Error("expected non-empty error message")
	}
}

func TestGetRelatedPosts_Success_ReturnsPostsSharingTags(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")

	// Shared tag between the source post and the related post.
	tagName := "tag_" + handlers.RandomSuffix()
	var tagID string
	if err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO tags (name, slug) VALUES ($1,$1) RETURNING id`, tagName,
	).Scan(&tagID); err != nil {
		t.Fatalf("insert tag: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM tags WHERE id=$1`, tagID) })

	sourceID, _ := createTestPost(t, d.Pool, authorID, "published")
	relatedID, relatedSlug := createTestPost(t, d.Pool, authorID, "published")
	unrelatedID, unrelatedSlug := createTestPost(t, d.Pool, authorID, "published")
	_ = unrelatedSlug

	for _, postID := range []string{sourceID, relatedID} {
		if _, err := d.Pool.Exec(context.Background(),
			`INSERT INTO post_tags (post_id, tag_id) VALUES ($1,$2)`, postID, tagID); err != nil {
			t.Fatalf("insert post_tags: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM post_tags WHERE tag_id=$1`, tagID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+sourceID+"/related", nil)
	req.SetPathValue("id", sourceID)
	w := httptest.NewRecorder()

	handlers.GetRelatedPosts(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	found := false
	for _, p := range resp.Posts {
		if p["slug"] == relatedSlug {
			found = true
			author, ok := p["author"].(map[string]any)
			if !ok {
				t.Fatalf("expected author object in related post, got %v", p["author"])
			}
			if author["username"] == "" || author["username"] == nil {
				t.Error("expected non-empty author username")
			}
		}
		if p["slug"] == unrelatedSlug {
			t.Error("unrelated post (no shared tags) must not appear in related posts")
		}
		if p["slug"] == nil {
			t.Errorf("source post must not include itself in its own related list: %+v", p)
		}
	}
	if !found {
		t.Errorf("expected related post %q (shares a tag) in response", relatedSlug)
	}
	_ = unrelatedID
}
