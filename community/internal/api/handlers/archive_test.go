package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestArchivePost_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/archive", nil)
	w := httptest.NewRecorder()

	handlers.ArchivePost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestArchivePost_PostNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/archive", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ArchivePost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestUnarchivePost_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/unarchive", nil)
	w := httptest.NewRecorder()

	handlers.UnarchivePost(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestUnarchivePost_PostNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/unarchive", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnarchivePost(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Live-DB tests: authorship enforcement + full archive/unarchive cycle ---

func TestArchivePost_NotOwner_Returns403_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	authorID, _ := mkUser13(t, pool, "author")
	_, otherUsername := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", authorID)

	postID := mkPost13(t, pool, authorID, "published")
	defer cleanup13(pool, "posts", "id", postID)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/archive", nil)
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: otherUsername, Role: "author"})
	w := httptest.NewRecorder()
	handlers.ArchivePost(d)(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when a non-owner tries to archive a post (IDOR check), got %d", w.Code)
	}
}

func TestArchiveUnarchive_FullCycle_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)

	authorID, authorUsername := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", authorID)

	postID := mkPost13(t, pool, authorID, "published")
	defer cleanup13(pool, "posts", "id", postID)

	archReq := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/archive", nil)
	archReq.SetPathValue("id", postID)
	archReq = withClaims(archReq, &auth.Claims{Sub: authorUsername, Role: "author"})
	archW := httptest.NewRecorder()
	handlers.ArchivePost(d)(archW, archReq)
	if archW.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", archW.Code, archW.Body.String())
	}

	var state string
	_ = pool.QueryRow(context.Background(), `SELECT state FROM posts WHERE id=$1`, postID).Scan(&state)
	if state != "archived" {
		t.Errorf("expected state=archived, got %q", state)
	}

	unReq := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/unarchive", nil)
	unReq.SetPathValue("id", postID)
	unReq = withClaims(unReq, &auth.Claims{Sub: authorUsername, Role: "author"})
	unW := httptest.NewRecorder()
	handlers.UnarchivePost(d)(unW, unReq)
	if unW.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", unW.Code, unW.Body.String())
	}

	var state2 string
	_ = pool.QueryRow(context.Background(), `SELECT state FROM posts WHERE id=$1`, postID).Scan(&state2)
	if state2 != "draft" {
		t.Errorf("expected state=draft after unarchive, got %q", state2)
	}

	// Unarchiving a non-archived post 404s (UnarchivePost's SELECT filters on state='archived').
	unAgainW := httptest.NewRecorder()
	handlers.UnarchivePost(d)(unAgainW, unReq)
	if unAgainW.Code != http.StatusNotFound {
		t.Errorf("expected 404 unarchiving a post that is not archived, got %d", unAgainW.Code)
	}
}
