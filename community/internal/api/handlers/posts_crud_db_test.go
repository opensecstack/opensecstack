package handlers_test

// DB-backed tests for posts_crud.go and posts_actions.go — success paths,
// error paths, and authorization (IDOR) checks that a stubbed "bad pool"
// cannot exercise because the handlers never reach a real query.
//
// Requires a reachable Postgres (see handlers.NewTestDBPool); tests skip
// automatically when it isn't available.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/citadel"
	"github.com/opensecstack/community/internal/config"
)

// dbDeps returns Deps wired to the shared real test DB, with Citadel in
// dry-run mode so PublishPost's Emit call doesn't hit the network.
func dbDeps(t *testing.T) handlers.Deps {
	t.Helper()
	pool := handlers.NewTestDBPool(t)
	return handlers.Deps{
		Pool:    pool,
		Cfg:     &config.Config{Node: "community-test"},
		Citadel: citadel.New("", nil, "", true),
	}
}

// createTestUser inserts a user with a random username and returns
// (id, username). The row is cleaned up automatically.
func createTestUser(t *testing.T, pool *pgxpool.Pool, role string) (id, username string) {
	t.Helper()
	username = "u_" + handlers.RandomSuffix()
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, display_name, role) VALUES ($1,$1,$2) RETURNING id`,
		username, role,
	).Scan(&id)
	if err != nil {
		t.Fatalf("createTestUser: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)
	return id, username
}

// createTestPost inserts a post authored by authorID and returns (id, slug).
func createTestPost(t *testing.T, pool *pgxpool.Pool, authorID, state string) (id, slug string) {
	t.Helper()
	slug = "post-" + handlers.RandomSuffix()
	err := pool.QueryRow(context.Background(),
		`INSERT INTO posts (author_id, title, slug, body, state, published_at)
		 VALUES ($1,$2,$3,$4,$5, CASE WHEN $5='published' THEN now() ELSE NULL END)
		 RETURNING id`,
		authorID, "Test Post "+slug, slug, "Some body content.", state,
	).Scan(&id)
	if err != nil {
		t.Fatalf("createTestPost: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM posts WHERE id=$1`, id)
	})
	return id, slug
}

// ---------------------------------------------------------------------------
// ListPosts / ListFeed
// ---------------------------------------------------------------------------

func TestListPosts_ReturnsPublishedPosts(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, slug := createTestPost(t, d.Pool, authorID, "published")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts?limit=50&offset=0", nil)
	w := httptest.NewRecorder()

	handlers.ListPosts(d)(w, req)

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
		t.Errorf("expected to find published post %q in list", slug)
	}
}

// ListFeed is a thin wrapper around ListPosts.
func TestListFeed_ReturnsPublishedPosts(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, slug := createTestPost(t, d.Pool, authorID, "published")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feed?limit=50&offset=0", nil)
	w := httptest.NewRecorder()

	handlers.ListFeed(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, p := range resp.Posts {
		if p["slug"] == slug {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find published post %q via ListFeed", slug)
	}
}

func TestListPosts_DoesNotReturnDraftPosts(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, slug := createTestPost(t, d.Pool, authorID, "draft")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts?limit=100&offset=0", nil)
	w := httptest.NewRecorder()

	handlers.ListPosts(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	for _, p := range resp.Posts {
		if p["slug"] == slug {
			t.Errorf("draft post %q must not appear in public listing", slug)
		}
	}
}

// ---------------------------------------------------------------------------
// GetPost
// ---------------------------------------------------------------------------

func TestGetPost_Success_ReturnsPostWithBody(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, slug := createTestPost(t, d.Pool, authorID, "published")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+slug, nil)
	req.SetPathValue("slug", slug)
	w := httptest.NewRecorder()

	handlers.GetPost(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["slug"] != slug {
		t.Errorf("expected slug %q, got %v", slug, resp["slug"])
	}
	if resp["body"] == nil || resp["body"] == "" {
		t.Error("expected non-empty body in GetPost response")
	}
}

// ---------------------------------------------------------------------------
// CreatePost
// ---------------------------------------------------------------------------

func TestCreatePost_Success_CreatesPostAndTags(t *testing.T) {
	d := dbDeps(t)
	_, username := createTestUser(t, d.Pool, "author")

	body := `{"title":"Hello World","body":"Some content here.","tags":["go","security"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreatePost(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == "" || resp["slug"] == "" {
		t.Fatalf("expected id and slug in response, got %+v", resp)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM posts WHERE id=$1`, resp["id"])
	})

	var title string
	if err := d.Pool.QueryRow(context.Background(), `SELECT title FROM posts WHERE id=$1`, resp["id"]).Scan(&title); err != nil {
		t.Fatalf("expected created post to exist: %v", err)
	}
	if title != "Hello World" {
		t.Errorf("expected title 'Hello World', got %q", title)
	}
}

func TestCreatePost_CreatesUserOnFirstPost(t *testing.T) {
	d := dbDeps(t)
	username := "newauthor_" + handlers.RandomSuffix()
	handlers.CleanupUserByUsername(t, d.Pool, username)

	body := `{"title":"First Post","body":"content"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts", strings.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreatePost(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM posts WHERE id=$1`, resp["id"])
	})

	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM users WHERE username=$1`, username).Scan(&count)
	if count != 1 {
		t.Errorf("expected auto-created user for new author, count=%d", count)
	}
}

// ---------------------------------------------------------------------------
// UpdatePost — success + IDOR
// ---------------------------------------------------------------------------

func TestUpdatePost_Success_AuthorCanUpdateOwnPost(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	id, _ := createTestPost(t, d.Pool, authorID, "draft")

	body := `{"title":"Updated Title","body":"Updated body content."}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/posts/"+id, strings.NewReader(body))
	req.SetPathValue("id", id)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdatePost(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var title string
	_ = d.Pool.QueryRow(context.Background(), `SELECT title FROM posts WHERE id=$1`, id).Scan(&title)
	if title != "Updated Title" {
		t.Errorf("expected title to be updated, got %q", title)
	}
}

// IDOR: a different, unrelated (non-moderator) user must not be able to
// edit someone else's post.
func TestUpdatePost_OtherUser_Returns403_IDOR(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	id, _ := createTestPost(t, d.Pool, authorID, "draft")
	_, attackerUsername := createTestUser(t, d.Pool, "author")

	body := `{"title":"Hijacked Title","body":"malicious content"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/posts/"+id, strings.NewReader(body))
	req.SetPathValue("id", id)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdatePost(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when non-owner edits post, got %d — body: %s", w.Code, w.Body.String())
	}
	var title string
	_ = d.Pool.QueryRow(context.Background(), `SELECT title FROM posts WHERE id=$1`, id).Scan(&title)
	if title == "Hijacked Title" {
		t.Error("post title must not have been changed by a non-owner")
	}
}

func TestUpdatePost_Moderator_CanUpdateOthersPost(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	id, _ := createTestPost(t, d.Pool, authorID, "draft")
	_, modUsername := createTestUser(t, d.Pool, "moderator")

	body := `{"title":"Moderated Title","body":"content"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/posts/"+id, strings.NewReader(body))
	req.SetPathValue("id", id)
	req = withClaims(req, &auth.Claims{Sub: modUsername, Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.UpdatePost(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected moderator to be able to update others' posts, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestUpdatePost_NotFound_Returns404(t *testing.T) {
	d := dbDeps(t)
	_, username := createTestUser(t, d.Pool, "author")

	body := `{"title":"x","body":"y"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/posts/00000000-0000-0000-0000-000000000000", strings.NewReader(body))
	req.SetPathValue("id", "00000000-0000-0000-0000-000000000000")
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdatePost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeletePost — success + IDOR
// ---------------------------------------------------------------------------

func TestDeletePost_Success_AuthorCanDeleteOwnPost(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	id, _ := createTestPost(t, d.Pool, authorID, "draft")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/"+id, nil)
	req.SetPathValue("id", id)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeletePost(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM posts WHERE id=$1`, id).Scan(&count)
	if count != 0 {
		t.Error("expected post to be deleted")
	}
}

// IDOR: a different, unrelated (non-moderator) user must not be able to
// delete someone else's post.
func TestDeletePost_OtherUser_Returns403_IDOR(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	id, _ := createTestPost(t, d.Pool, authorID, "draft")
	_, attackerUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/"+id, nil)
	req.SetPathValue("id", id)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeletePost(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when non-owner deletes post, got %d — body: %s", w.Code, w.Body.String())
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM posts WHERE id=$1`, id).Scan(&count)
	if count != 1 {
		t.Error("post must still exist after forbidden delete attempt")
	}
}

func TestDeletePost_NotFound_Returns404(t *testing.T) {
	d := dbDeps(t)
	_, username := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/00000000-0000-0000-0000-000000000000", nil)
	req.SetPathValue("id", "00000000-0000-0000-0000-000000000000")
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeletePost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// PublishPost — success + IDOR
// ---------------------------------------------------------------------------

func TestPublishPost_Success_AuthorCanPublishOwnDraft(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	id, _ := createTestPost(t, d.Pool, authorID, "draft")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+id+"/publish", nil)
	req.SetPathValue("id", id)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.PublishPost(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var state string
	_ = d.Pool.QueryRow(context.Background(), `SELECT state FROM posts WHERE id=$1`, id).Scan(&state)
	if state != "published" {
		t.Errorf("expected state=published, got %q", state)
	}
}

// IDOR: a different, unrelated (non-moderator) user must not be able to
// publish someone else's draft.
func TestPublishPost_OtherUser_Returns403_IDOR(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	id, _ := createTestPost(t, d.Pool, authorID, "draft")
	_, attackerUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+id+"/publish", nil)
	req.SetPathValue("id", id)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.PublishPost(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when non-owner publishes post, got %d — body: %s", w.Code, w.Body.String())
	}
	var state string
	_ = d.Pool.QueryRow(context.Background(), `SELECT state FROM posts WHERE id=$1`, id).Scan(&state)
	if state == "published" {
		t.Error("post must not have been published by a non-owner")
	}
}

func TestPublishPost_AlreadyPublished_Returns404(t *testing.T) {
	d := dbDeps(t)
	authorID, authorUsername := createTestUser(t, d.Pool, "author")
	id, _ := createTestPost(t, d.Pool, authorID, "published")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+id+"/publish", nil)
	req.SetPathValue("id", id)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.PublishPost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for already-published post (query filters state='draft'), got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// ListFollowingFeed
// ---------------------------------------------------------------------------

func TestListFollowingFeed_Success_ReturnsFollowedAuthorsPosts(t *testing.T) {
	d := dbDeps(t)
	followerID, followerUsername := createTestUser(t, d.Pool, "author")
	followedID, _ := createTestUser(t, d.Pool, "author")
	_, slug := createTestPost(t, d.Pool, followedID, "published")

	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO follows (follower_id, following_id) VALUES ($1,$2)`, followerID, followedID)
	if err != nil {
		t.Fatalf("insert follow: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM follows WHERE follower_id=$1 AND following_id=$2`, followerID, followedID)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feed/following", nil)
	req = withClaims(req, &auth.Claims{Sub: followerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListFollowingFeed(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, p := range resp.Posts {
		if p["slug"] == slug {
			found = true
		}
	}
	if !found {
		t.Errorf("expected followed author's post %q in following feed", slug)
	}
}

func TestListFollowingFeed_UnresolvableUser_ReturnsEmptyList(t *testing.T) {
	d := dbDeps(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feed/following", nil)
	req = withClaims(req, &auth.Claims{Sub: "nonexistent_" + handlers.RandomSuffix(), Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListFollowingFeed(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Posts []map[string]any `json:"posts"`
		Count int              `json:"count"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count != 0 {
		t.Errorf("expected empty feed for unresolvable user, got count=%d", resp.Count)
	}
}
