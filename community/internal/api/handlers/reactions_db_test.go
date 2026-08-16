package handlers_test

// DB-backed tests for reactions.go — success paths and the
// UNIQUE(post_id, user_id, kind) constraint's effect on double-reacting.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestGetPostReactions_Success_ReturnsCountsAndViewerReactions(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	viewerID, viewerUsername := createTestUser(t, d.Pool, "author")

	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO reactions (post_id, user_id, kind) VALUES ($1,$2,'fire')`, postID, viewerID)
	if err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+postID+"/reactions", nil)
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: viewerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetPostReactions(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Reactions     map[string]int `json:"reactions"`
		UserReactions []string       `json:"user_reactions"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Reactions["fire"] != 1 {
		t.Errorf("expected fire count=1, got %+v", resp.Reactions)
	}
	found := false
	for _, k := range resp.UserReactions {
		if k == "fire" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected viewer's own 'fire' reaction in user_reactions, got %v", resp.UserReactions)
	}
}

func TestGetPostReactions_Unauthenticated_ReturnsPublicCountsOnly(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	otherID, _ := createTestUser(t, d.Pool, "author")

	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO reactions (post_id, user_id, kind) VALUES ($1,$2,'like')`, postID, otherID)
	if err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/posts/"+postID+"/reactions", nil)
	req.SetPathValue("id", postID)
	// No claims injected — public/unauthenticated request.
	w := httptest.NewRecorder()

	handlers.GetPostReactions(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Reactions     map[string]int `json:"reactions"`
		UserReactions []string       `json:"user_reactions"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Reactions["like"] != 1 {
		t.Errorf("expected public count like=1 even unauthenticated, got %+v", resp.Reactions)
	}
	if len(resp.UserReactions) != 0 {
		t.Errorf("expected empty user_reactions when unauthenticated, got %v", resp.UserReactions)
	}
}

// ---------------------------------------------------------------------------
// AddReaction — success + double-react constraint
// ---------------------------------------------------------------------------

func TestAddReaction_Success_InsertsReaction(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	_, reactorUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/reactions", strings.NewReader(`{"kind":"heart"}`))
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: reactorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.AddReaction(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM reactions WHERE post_id=$1 AND kind='heart'`, postID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 heart reaction, got %d", count)
	}
}

// Repeated identical (post, user, kind) reactions must not duplicate rows —
// enforced by the reactions table's UNIQUE(post_id, user_id, kind)
// constraint plus ON CONFLICT DO NOTHING in the handler.
func TestAddReaction_DoubleReactSameKind_DoesNotDuplicate(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	_, reactorUsername := createTestUser(t, d.Pool, "author")

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/reactions", strings.NewReader(`{"kind":"heart"}`))
		req.SetPathValue("id", postID)
		req = withClaims(req, &auth.Claims{Sub: reactorUsername, Role: "author"})
		w := httptest.NewRecorder()
		handlers.AddReaction(d)(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("call %d: expected 204, got %d — body: %s", i, w.Code, w.Body.String())
		}
	}

	var count int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM reactions WHERE post_id=$1 AND kind='heart'`, postID).Scan(&count)
	if count != 1 {
		t.Errorf("expected exactly 1 reaction after double-react with same kind, got %d", count)
	}
}

// A single user reacting with multiple distinct kinds is allowed by design
// (multi-emoji reaction bar) — this is not a bypass of the uniqueness
// constraint, which is scoped per (post, user, kind).
func TestAddReaction_SameUserDifferentKinds_BothPersist(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	_, reactorUsername := createTestUser(t, d.Pool, "author")

	for _, kind := range []string{"heart", "fire"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/reactions", strings.NewReader(`{"kind":"`+kind+`"}`))
		req.SetPathValue("id", postID)
		req = withClaims(req, &auth.Claims{Sub: reactorUsername, Role: "author"})
		w := httptest.NewRecorder()
		handlers.AddReaction(d)(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("kind %s: expected 204, got %d — body: %s", kind, w.Code, w.Body.String())
		}
	}

	var count int
	_ = d.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM reactions WHERE post_id=$1`, postID).Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 distinct-kind reactions to persist, got %d", count)
	}
}

func TestAddReaction_InvalidKind_Returns400(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	_, reactorUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/"+postID+"/reactions", strings.NewReader(`{"kind":"not-a-real-kind"}`))
	req.SetPathValue("id", postID)
	req = withClaims(req, &auth.Claims{Sub: reactorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.AddReaction(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a kind violating the CHECK constraint, got %d — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// RemoveReaction — success + cross-user scoping
// ---------------------------------------------------------------------------

func TestRemoveReaction_Success_DeletesOwnReaction(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	reactorID, reactorUsername := createTestUser(t, d.Pool, "author")

	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO reactions (post_id, user_id, kind) VALUES ($1,$2,'heart')`, postID, reactorID)
	if err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/"+postID+"/reactions/heart", nil)
	req.SetPathValue("id", postID)
	req.SetPathValue("kind", "heart")
	req = withClaims(req, &auth.Claims{Sub: reactorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RemoveReaction(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM reactions WHERE post_id=$1 AND user_id=$2`, postID, reactorID).Scan(&count)
	if count != 0 {
		t.Error("expected reaction to be removed")
	}
}

// Confirms RemoveReaction is scoped to the caller's own resolved user_id —
// another user's reaction on the same post/kind must survive.
func TestRemoveReaction_OnlyRemovesCallersOwnReaction(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	victimID, _ := createTestUser(t, d.Pool, "author")
	_, attackerUsername := createTestUser(t, d.Pool, "author")

	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO reactions (post_id, user_id, kind) VALUES ($1,$2,'heart')`, postID, victimID)
	if err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/"+postID+"/reactions/heart", nil)
	req.SetPathValue("id", postID)
	req.SetPathValue("kind", "heart")
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RemoveReaction(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 (no-op delete), got %d", w.Code)
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM reactions WHERE post_id=$1 AND user_id=$2`, postID, victimID).Scan(&count)
	if count != 1 {
		t.Error("another user's reaction must not be removable by a different caller")
	}
}

func TestRemoveReaction_NoClaims_Returns401(t *testing.T) {
	d := dbDeps(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/posts/some-id/reactions/heart", nil)
	req.SetPathValue("id", "some-id")
	req.SetPathValue("kind", "heart")
	w := httptest.NewRecorder()

	handlers.RemoveReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}
