package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestGetUserStats_UserNotFoundRealDB_Returns404(t *testing.T) {
	d := dbDeps(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/nosuchuser_"+handlers.RandomSuffix()+"/stats", nil)
	req.SetPathValue("username", "nosuchuser_"+handlers.RandomSuffix())
	w := httptest.NewRecorder()

	handlers.GetUserStats(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent user, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestGetUserStats_Success_ReturnsCounts(t *testing.T) {
	d := dbDeps(t)
	authorID, username := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	draftID, _ := createTestPost(t, d.Pool, authorID, "draft")

	reactorID, _ := createTestUser(t, d.Pool, "author")
	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO reactions (post_id, user_id, kind) VALUES ($1,$2,'like')`, postID, reactorID); err != nil {
		t.Fatalf("insert reaction: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM reactions WHERE post_id=$1`, postID) })

	// A reaction on the draft post must not be counted (only published posts count).
	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO reactions (post_id, user_id, kind) VALUES ($1,$2,'like')`, draftID, reactorID); err != nil {
		t.Fatalf("insert draft reaction: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM reactions WHERE post_id=$1`, draftID) })

	if _, err := d.Pool.Exec(context.Background(),
		`INSERT INTO post_views_daily (post_id, day, count) VALUES ($1, CURRENT_DATE, 7)`, postID); err != nil {
		t.Fatalf("insert views: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM post_views_daily WHERE post_id=$1`, postID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+username+"/stats", nil)
	req.SetPathValue("username", username)
	w := httptest.NewRecorder()

	handlers.GetUserStats(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		PostCount     int64 `json:"post_count"`
		ReactionCount int64 `json:"reaction_count"`
		ViewCount     int64 `json:"view_count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.PostCount != 1 {
		t.Errorf("expected post_count=1 (published only), got %d", resp.PostCount)
	}
	if resp.ReactionCount != 1 {
		t.Errorf("expected reaction_count=1 (published post only), got %d", resp.ReactionCount)
	}
	if resp.ViewCount != 7 {
		t.Errorf("expected view_count=7, got %d", resp.ViewCount)
	}
}

func TestGetUserStats_UserNotFound_Returns500(t *testing.T) {
	// With an unreachable DB, the initial user lookup fails with a
	// connection error (not pgx.ErrNoRows), so the handler takes the
	// generic 500 branch rather than the 404 "user not found" branch.
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice/stats", nil)
	req.SetPathValue("username", "alice")
	w := httptest.NewRecorder()

	handlers.GetUserStats(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db connection error, got %d — body: %s", w.Code, w.Body.String())
	}
}
