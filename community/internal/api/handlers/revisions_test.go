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

func TestListPostRevisions_Success_OwnerSeesRevisions(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "draft")

	var revID string
	if err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO post_revisions (post_id, title, body) VALUES ($1,'Old Title','Old body') RETURNING id`,
		postID).Scan(&revID); err != nil {
		t.Fatalf("insert revision: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM post_revisions WHERE id=$1`, revID) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+postID+"/revisions", nil)
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListPostRevisions(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Revisions []map[string]any `json:"revisions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, r := range resp.Revisions {
		if r["id"] == revID {
			found = true
			if r["title"] != "Old Title" {
				t.Errorf("expected title 'Old Title', got %v", r["title"])
			}
		}
	}
	if !found {
		t.Errorf("expected revision %q in response", revID)
	}
}

// IDOR: a user who does not own the post must not see its revision history.
func TestListPostRevisions_NonOwner_Returns403_IDOR(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "draft")
	_, attackerUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+postID+"/revisions", nil)
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListPostRevisions(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner requesting revisions, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestListPostRevisions_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/1/revisions", nil)
	w := httptest.NewRecorder()

	handlers.ListPostRevisions(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestListPostRevisions_PostNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/1/revisions", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListPostRevisions(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when post/author cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
}
