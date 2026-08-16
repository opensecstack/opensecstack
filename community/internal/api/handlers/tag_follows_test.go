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

func TestFollowTag_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tags/go/follow", nil)
	w := httptest.NewRecorder()

	handlers.FollowTag(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestFollowTag_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tags/go/follow", nil)
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.FollowTag(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when user cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestUnfollowTag_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tags/go/follow", nil)
	w := httptest.NewRecorder()

	handlers.UnfollowTag(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestUnfollowTag_UserNotFound_StillReturns204 verifies UnfollowTag treats
// an unresolvable user as an idempotent no-op (204) rather than an error —
// unfollowing something you were never following should not fail.
func TestUnfollowTag_UserNotFound_StillReturns204(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tags/go/follow", nil)
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnfollowTag(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestGetTagFollowStatus_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/go/follow", nil)
	w := httptest.NewRecorder()

	handlers.GetTagFollowStatus(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestGetTagFollowStatus_UserNotFound_ReturnsFalse verifies the handler
// fails closed to "following: false" rather than an error when the caller
// can't be resolved.
func TestGetTagFollowStatus_UserNotFound_ReturnsFalse(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/go/follow", nil)
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetTagFollowStatus(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["following"] {
		t.Error("expected following=false when user cannot be resolved")
	}
}

func TestListFollowingTagsFeed_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/tags/feed", nil)
	w := httptest.NewRecorder()

	handlers.ListFollowingTagsFeed(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestListFollowingTagsFeed_UserNotFound_ReturnsEmptyList verifies the
// handler returns an empty (not error) feed when the caller can't be
// resolved, matching its degrade-gracefully design.
func TestListFollowingTagsFeed_UserNotFound_ReturnsEmptyList(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/tags/feed", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListFollowingTagsFeed(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []any `json:"posts"`
		Count int   `json:"count"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count != 0 || len(resp.Posts) != 0 {
		t.Errorf("expected empty feed, got count=%d posts=%v", resp.Count, resp.Posts)
	}
}

// ---------- live-DB success-path tests ----------

func TestFollowTag_Success_Then_Conflict_Then_StatusTrue_Then_Unfollow(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "tf_" + handlers.RandomSuffix()
	slug := "tftag-" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)
	if _, err := pool.Exec(context.Background(), `INSERT INTO tags (name, slug) VALUES ($1,$2)`, "TF Tag "+slug, slug); err != nil {
		t.Fatalf("insert tag: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tags WHERE slug=$1`, slug) })

	// Follow: first call succeeds.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tags/"+slug+"/follow", nil)
	req.SetPathValue("slug", slug)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()
	handlers.FollowTag(d)(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on first follow, got %d — body: %s", w.Code, w.Body.String())
	}

	// Follow again: conflict.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/tags/"+slug+"/follow", nil)
	req2.SetPathValue("slug", slug)
	req2 = withClaims(req2, &auth.Claims{Sub: username, Role: "author"})
	w2 := httptest.NewRecorder()
	handlers.FollowTag(d)(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 when already following, got %d — body: %s", w2.Code, w2.Body.String())
	}

	// Status: true.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/tags/"+slug+"/follow", nil)
	req3.SetPathValue("slug", slug)
	req3 = withClaims(req3, &auth.Claims{Sub: username, Role: "author"})
	w3 := httptest.NewRecorder()
	handlers.GetTagFollowStatus(d)(w3, req3)
	var statusResp map[string]bool
	_ = json.NewDecoder(w3.Body).Decode(&statusResp)
	if !statusResp["following"] {
		t.Error("expected following=true after successful follow")
	}

	// Unfollow: succeeds.
	req4 := httptest.NewRequest(http.MethodDelete, "/api/v1/tags/"+slug+"/follow", nil)
	req4.SetPathValue("slug", slug)
	req4 = withClaims(req4, &auth.Claims{Sub: username, Role: "author"})
	w4 := httptest.NewRecorder()
	handlers.UnfollowTag(d)(w4, req4)
	if w4.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on unfollow, got %d", w4.Code)
	}

	// Status: false again.
	req5 := httptest.NewRequest(http.MethodGet, "/api/v1/tags/"+slug+"/follow", nil)
	req5.SetPathValue("slug", slug)
	req5 = withClaims(req5, &auth.Claims{Sub: username, Role: "author"})
	w5 := httptest.NewRecorder()
	handlers.GetTagFollowStatus(d)(w5, req5)
	var statusResp2 map[string]bool
	_ = json.NewDecoder(w5.Body).Decode(&statusResp2)
	if statusResp2["following"] {
		t.Error("expected following=false after unfollow")
	}
}

func TestFollowTag_TagNotFound_Returns404(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "tf_" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tags/no-such-tag/follow", nil)
	req.SetPathValue("slug", "no-such-tag-"+handlers.RandomSuffix())
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.FollowTag(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent tag, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestListFollowingTagsFeed_Success_ReturnsFollowedPost(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "tf_" + handlers.RandomSuffix()
	slug := "tffeed-" + handlers.RandomSuffix()

	var userID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username) VALUES ($1) RETURNING id`, username,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	var tagID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tags (name, slug) VALUES ($1,$2) RETURNING id`, "TF Feed "+slug, slug,
	).Scan(&tagID); err != nil {
		t.Fatalf("insert tag: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tags WHERE slug=$1`, slug) })

	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tag_follows (user_id, tag_id) VALUES ($1,$2)`, userID, tagID,
	); err != nil {
		t.Fatalf("insert tag_follows: %v", err)
	}

	postSlug := "tffeedpost-" + handlers.RandomSuffix()
	var postID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO posts (author_id, title, slug, body, state, published_at)
		 VALUES ($1,$2,$3,'body','published', now()) RETURNING id`,
		userID, "Feed Post", postSlug,
	).Scan(&postID); err != nil {
		t.Fatalf("insert post: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO post_tags (post_id, tag_id) VALUES ($1,$2)`, postID, tagID,
	); err != nil {
		t.Fatalf("insert post_tags: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/tags/feed", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListFollowingTagsFeed(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count == 0 {
		t.Error("expected at least one post from a followed tag")
	}
}
