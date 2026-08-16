package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestGetUser_NotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/nobody", nil)
	req.SetPathValue("username", "nobody")
	w := httptest.NewRecorder()

	handlers.GetUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGetUserPinnedPost_NonePinned_ReturnsNullPost(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/nobody/pinned-post", nil)
	req.SetPathValue("username", "nobody")
	w := httptest.NewRecorder()

	handlers.GetUserPinnedPost(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["post"] != nil {
		t.Errorf("expected post=nil, got %v", resp["post"])
	}
}

func TestListUserPosts_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/nobody/posts", nil)
	req.SetPathValue("username", "nobody")
	w := httptest.NewRecorder()

	handlers.ListUserPosts(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on db error, got %d", w.Code)
	}
}

func TestGetMyPosts_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/posts", nil)
	w := httptest.NewRecorder()

	handlers.GetMyPosts(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestGetMyPosts_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/posts", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetMyPosts(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on db error, got %d", w.Code)
	}
}

func TestSearchUsers_EmptyQuery_ReturnsEmptyList(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/search", nil)
	w := httptest.NewRecorder()

	handlers.SearchUsers(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	users, _ := resp["users"].([]any)
	if len(users) != 0 {
		t.Errorf("expected empty users list for empty query, got %v", resp["users"])
	}
}

func TestSearchUsers_DBError_ReturnsEmptyList(t *testing.T) {
	// SearchUsers deliberately degrades to an empty result on DB error
	// rather than a 500 — it backs an autocomplete-style UI.
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/search?q=al", nil)
	w := httptest.NewRecorder()

	handlers.SearchUsers(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even on db error, got %d", w.Code)
	}
}

func TestUpdateMe_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()

	handlers.UpdateMe(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestUpdateMe_BadJSON_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdateMe(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestUpdateMe_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me", bytes.NewReader([]byte(`{"display_name":"Alice"}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdateMe(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on db error, got %d", w.Code)
	}
}

// --- Live-DB success paths ---

func TestGetUser_Success_ReturnsProfile(t *testing.T) {
	d := requireLiveDB(t)
	_, username := seedTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+username, nil)
	req.SetPathValue("username", username)
	w := httptest.NewRecorder()

	handlers.GetUser(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Username != username {
		t.Errorf("expected username %q, got %q", username, resp.Username)
	}
	if resp.Role != "author" {
		t.Errorf("expected role author, got %q", resp.Role)
	}
}

func TestGetUserPinnedPost_Success_ReturnsPinnedPost(t *testing.T) {
	d := requireLiveDB(t)
	authorID, authorUsername := seedTestUser(t, d.Pool, "author")
	postID, postSlug := seedTestPost(t, d.Pool, authorID)

	if _, err := d.Pool.Exec(context.Background(), `UPDATE posts SET pinned=true WHERE id=$1`, postID); err != nil {
		t.Fatalf("pin post: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+authorUsername+"/pinned-post", nil)
	req.SetPathValue("username", authorUsername)
	w := httptest.NewRecorder()

	handlers.GetUserPinnedPost(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Post *struct {
			Slug string `json:"slug"`
		} `json:"post"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Post == nil || resp.Post.Slug != postSlug {
		t.Errorf("expected pinned post slug %q, got %v", postSlug, resp.Post)
	}
}

func TestListUserPosts_Success_ReturnsPublishedPost(t *testing.T) {
	d := requireLiveDB(t)
	authorID, authorUsername := seedTestUser(t, d.Pool, "author")
	_, postSlug := seedTestPost(t, d.Pool, authorID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+authorUsername+"/posts", nil)
	req.SetPathValue("username", authorUsername)
	w := httptest.NewRecorder()

	handlers.ListUserPosts(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []struct {
			Slug string `json:"slug"`
		} `json:"posts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, p := range resp.Posts {
		if p.Slug == postSlug {
			found = true
		}
	}
	if !found {
		t.Error("expected seeded post to appear in ListUserPosts")
	}
}

func TestGetMyPosts_Success_ReturnsOwnPost(t *testing.T) {
	d := requireLiveDB(t)
	authorID, authorUsername := seedTestUser(t, d.Pool, "author")
	_, postSlug := seedTestPost(t, d.Pool, authorID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/posts", nil)
	req = withClaims(req, &auth.Claims{Sub: authorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetMyPosts(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Posts []struct {
			Slug string `json:"slug"`
		} `json:"posts"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, p := range resp.Posts {
		if p.Slug == postSlug {
			found = true
		}
	}
	if !found {
		t.Error("expected seeded post to appear in GetMyPosts")
	}
}

func TestSearchUsers_Success_FindsMatchingPrefix(t *testing.T) {
	d := requireLiveDB(t)
	_, username := seedTestUser(t, d.Pool, "author")

	// username is "gru_<uuid>" — search on that stable prefix.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/search?q="+username[:8], nil)
	w := httptest.NewRecorder()

	handlers.SearchUsers(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Users []struct {
			Username string `json:"username"`
		} `json:"users"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, u := range resp.Users {
		if u.Username == username {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find seeded user %q in search results", username)
	}
}

func TestUpdateMe_Success_UpdatesProfile(t *testing.T) {
	d := requireLiveDB(t)
	_, username := seedTestUser(t, d.Pool, "author")

	body := `{"display_name":"Updated Name","bio":"new bio","website":"https://example.test",
	          "github_username":"gh","twitter_username":"tw","location":"Earth",
	          "certifications":"OSCP","specialization":"pentest"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me", bytes.NewReader([]byte(body)))
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.UpdateMe(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+username, nil)
	getReq.SetPathValue("username", username)
	getW := httptest.NewRecorder()
	handlers.GetUser(d)(getW, getReq)

	var resp struct {
		DisplayName string `json:"display_name"`
		Bio         string `json:"bio"`
	}
	_ = json.NewDecoder(getW.Body).Decode(&resp)
	if resp.DisplayName != "Updated Name" {
		t.Errorf("expected display_name to be updated, got %q", resp.DisplayName)
	}
	if resp.Bio != "new bio" {
		t.Errorf("expected bio to be updated, got %q", resp.Bio)
	}
}
