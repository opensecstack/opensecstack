package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestPinPost_Success_PinsAndUnpinsPreviouslyPinned(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, adminUsername := createTestUser(t, d.Pool, "admin")

	firstID, _ := createTestPost(t, d.Pool, authorID, "published")
	secondID, _ := createTestPost(t, d.Pool, authorID, "published")

	// Pin the first post.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+firstID+"/pin", nil)
	req.SetPathValue("id", firstID)
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()
	handlers.PinPost(d)(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 pinning first post, got %d — body: %s", w.Code, w.Body.String())
	}

	var pinned bool
	_ = d.Pool.QueryRow(context.Background(), `SELECT pinned FROM posts WHERE id=$1`, firstID).Scan(&pinned)
	if !pinned {
		t.Fatal("expected first post to be pinned")
	}

	// Pinning the second post must unpin the first (only one pinned at a time).
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+secondID+"/pin", nil)
	req2.SetPathValue("id", secondID)
	req2 = withClaims(req2, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w2 := httptest.NewRecorder()
	handlers.PinPost(d)(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Fatalf("expected 204 pinning second post, got %d", w2.Code)
	}

	_ = d.Pool.QueryRow(context.Background(), `SELECT pinned FROM posts WHERE id=$1`, firstID).Scan(&pinned)
	if pinned {
		t.Error("expected first post to be unpinned once a second post is pinned")
	}
	var secondPinned bool
	_ = d.Pool.QueryRow(context.Background(), `SELECT pinned FROM posts WHERE id=$1`, secondID).Scan(&secondPinned)
	if !secondPinned {
		t.Error("expected second post to be pinned")
	}

	// Pinning writes an audit_log row.
	var auditCount int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_log WHERE action='pin_post' AND target_id=$1`, secondID).Scan(&auditCount)
	if auditCount != 1 {
		t.Errorf("expected exactly one pin_post audit_log entry for the second post, got %d", auditCount)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM audit_log WHERE action='pin_post' AND target_id IN ($1,$2)`, firstID, secondID)
	})
}

func TestPinPost_NotFound_Returns404(t *testing.T) {
	d := dbDeps(t)
	_, adminUsername := createTestUser(t, d.Pool, "admin")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/00000000-0000-0000-0000-000000000000/pin", nil)
	req.SetPathValue("id", "00000000-0000-0000-0000-000000000000")
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()

	handlers.PinPost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent post, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestUnpinPost_Success_ClearsPin(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	_, adminUsername := createTestUser(t, d.Pool, "admin")
	id, _ := createTestPost(t, d.Pool, authorID, "published")

	if _, err := d.Pool.Exec(context.Background(), `UPDATE posts SET pinned=true WHERE id=$1`, id); err != nil {
		t.Fatalf("pre-pin post: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/"+id+"/pin", nil)
	req.SetPathValue("id", id)
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()

	handlers.UnpinPost(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
	var pinned bool
	_ = d.Pool.QueryRow(context.Background(), `SELECT pinned FROM posts WHERE id=$1`, id).Scan(&pinned)
	if pinned {
		t.Error("expected post to be unpinned")
	}
}

func TestPinPost_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/pin", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.PinPost(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestPinPost_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/pin", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.PinPost(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestUnpinPost_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/1/pin", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnpinPost(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestUnpinPost_Admin_Returns204(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/1/pin", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.UnpinPost(d)(w, req)

	// UnpinPost ignores the Exec error (best-effort unpin), so it always
	// reaches the 204 response even when the DB call fails.
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
}
