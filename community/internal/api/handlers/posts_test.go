package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

// postDepsNoPool returns Deps with a nil pool and minimal config — used when
// we only need to exercise early-return paths that don't touch the DB.
func postDepsNoPool() handlers.Deps {
	return handlers.Deps{
		Cfg: &config.Config{
			JWTSecret: "unit-test-secret",
			JWTIssuer: "test",
			TokenTTL:  time.Hour,
		},
	}
}

// ---------------------------------------------------------------------------
// CreatePost — auth guard
// ---------------------------------------------------------------------------

func TestCreatePost_NoAuth_Returns401(t *testing.T) {
	d := postDepsNoPool()

	body, _ := json.Marshal(map[string]any{
		"title": "My Post",
		"body":  "Content here.",
		"tags":  []string{"test"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No claims injected.
	w := httptest.NewRecorder()

	handlers.CreatePost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("CreatePost: expected 401 without auth, got %d", w.Code)
	}
}

func TestCreatePost_EmptyTitle_Returns400(t *testing.T) {
	d := postDepsNoPool()

	body, _ := json.Marshal(map[string]any{
		"title": "   ",
		"body":  "Content here.",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	// With a nil pool and a whitespace-only title the handler must reject
	// before hitting the DB.
	handlers.CreatePost(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("CreatePost: expected 400 for empty title, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] == "" {
		t.Error("expected non-empty error message")
	}
}

func TestCreatePost_BadJSON_Returns400(t *testing.T) {
	d := postDepsNoPool()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts", bytes.NewReader([]byte(`{bad}`)))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreatePost(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("CreatePost: expected 400 for bad JSON, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// UpdatePost — auth guard
// ---------------------------------------------------------------------------

func TestUpdatePost_NoAuth_Returns401(t *testing.T) {
	d := postDepsNoPool()

	body, _ := json.Marshal(map[string]any{"title": "Updated", "body": "New content."})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/posts/some-id", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.UpdatePost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("UpdatePost: expected 401 without auth, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// DeletePost — auth guard
// ---------------------------------------------------------------------------

func TestDeletePost_NoAuth_Returns401(t *testing.T) {
	d := postDepsNoPool()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/some-id", nil)
	w := httptest.NewRecorder()

	handlers.DeletePost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("DeletePost: expected 401 without auth, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// PublishPost — auth guard
// ---------------------------------------------------------------------------

func TestPublishPost_NoAuth_Returns401(t *testing.T) {
	d := postDepsNoPool()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/some-id/publish", nil)
	w := httptest.NewRecorder()

	handlers.PublishPost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("PublishPost: expected 401 without auth, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// PublishPost — post not found (auth present, DB returns no rows)
// ---------------------------------------------------------------------------

func TestPublishPost_NotFound_Returns404(t *testing.T) {
	// Pool is unreachable — QueryRow.Scan will fail, which the handler
	// treats as "post not found or not in draft" → 404.
	d := newDepsWithBadDB(t)
	d.Cfg = &config.Config{
		JWTSecret: "unit-test-secret",
		JWTIssuer: "test",
		TokenTTL:  time.Hour,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/nonexistent-id/publish", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.PublishPost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("PublishPost: expected 404 for nonexistent post, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// GetPost — post not found (DB returns no rows)
// ---------------------------------------------------------------------------

func TestGetPost_NotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	d.Cfg = &config.Config{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/no-such-slug", nil)
	w := httptest.NewRecorder()

	handlers.GetPost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("GetPost: expected 404 for missing post, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] == "" {
		t.Error("expected non-empty error in 404 response")
	}
}

// ---------------------------------------------------------------------------
// ListFollowingFeed — auth guard
// ---------------------------------------------------------------------------

func TestListFollowingFeed_NoAuth_Returns401(t *testing.T) {
	d := postDepsNoPool()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feed/following", nil)
	w := httptest.NewRecorder()

	handlers.ListFollowingFeed(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("ListFollowingFeed: expected 401 without auth, got %d", w.Code)
	}
}
