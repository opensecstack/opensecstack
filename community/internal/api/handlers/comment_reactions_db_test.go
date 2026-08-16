package handlers_test

// DB-backed tests for comment_reactions.go — success paths and the
// per-(comment,user,kind) uniqueness constraint enforced by the schema
// (comment_reactions PRIMARY KEY (comment_id, user_id, kind)).

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

func TestAddCommentReaction_Success_InsertsReaction(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)
	_, reactorUsername := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/"+commentID+"/reactions", nil)
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: reactorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.AddCommentReaction(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM comment_reactions WHERE comment_id=$1 AND kind='heart'`, commentID).Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 heart reaction, got %d", count)
	}
}

// Repeated calls must not duplicate the reaction — the handler relies on
// ON CONFLICT DO NOTHING backed by the table's composite primary key.
func TestAddCommentReaction_DoubleReact_DoesNotDuplicate(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)
	_, reactorUsername := createTestUser(t, d.Pool, "author")

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/"+commentID+"/reactions", nil)
		req.SetPathValue("id", commentID)
		req = withClaims(req, &auth.Claims{Sub: reactorUsername, Role: "author"})
		w := httptest.NewRecorder()
		handlers.AddCommentReaction(d)(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("call %d: expected 200, got %d", i, w.Code)
		}
	}

	var count int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM comment_reactions WHERE comment_id=$1 AND kind='heart'`, commentID).Scan(&count)
	if count != 1 {
		t.Errorf("expected exactly 1 reaction after double-react, got %d (one-reaction constraint bypassed)", count)
	}
}

func TestRemoveCommentReaction_Success_DeletesReaction(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)
	reactorID, reactorUsername := createTestUser(t, d.Pool, "author")

	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO comment_reactions (comment_id, user_id, kind) VALUES ($1,$2,'heart')`, commentID, reactorID)
	if err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/comments/"+commentID+"/reactions", nil)
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: reactorUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RemoveCommentReaction(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM comment_reactions WHERE comment_id=$1 AND user_id=$2`, commentID, reactorID).Scan(&count)
	if count != 0 {
		t.Error("expected reaction to be removed")
	}
}

// IDOR-style check: user A's reaction must survive user B calling remove —
// the DELETE is scoped by the caller's own resolved user_id, not an
// attacker-supplied id, so there's no cross-user deletion path here. This
// test documents/pins that scoping.
func TestRemoveCommentReaction_OtherUsersReactionUnaffected(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)
	victimID, _ := createTestUser(t, d.Pool, "author")
	_, attackerUsername := createTestUser(t, d.Pool, "author")

	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO comment_reactions (comment_id, user_id, kind) VALUES ($1,$2,'heart')`, commentID, victimID)
	if err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/comments/"+commentID+"/reactions", nil)
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.RemoveCommentReaction(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (fail-open ok response), got %d", w.Code)
	}
	var count int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM comment_reactions WHERE comment_id=$1 AND user_id=$2`, commentID, victimID).Scan(&count)
	if count != 1 {
		t.Error("another user's reaction must not be removable by a different caller")
	}
}

// ---------------------------------------------------------------------------
// ToggleCommentReaction — success
// ---------------------------------------------------------------------------

func TestToggleCommentReaction_Success_AddsThenRemoves(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)
	_, reactorUsername := createTestUser(t, d.Pool, "author")

	// First toggle: adds.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/"+commentID+"/reactions/toggle", strings.NewReader(`{"kind":"fire"}`))
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: reactorUsername, Role: "author"})
	w := httptest.NewRecorder()
	handlers.ToggleCommentReaction(d)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first toggle: expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp1 struct {
		Counts        map[string]int  `json:"counts"`
		UserReactions map[string]bool `json:"user_reactions"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp1)
	if resp1.Counts["fire"] != 1 || !resp1.UserReactions["fire"] {
		t.Errorf("expected fire count=1 and user_reactions.fire=true after add, got %+v", resp1)
	}

	// Second toggle: removes.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/comments/"+commentID+"/reactions/toggle", strings.NewReader(`{"kind":"fire"}`))
	req2.SetPathValue("id", commentID)
	req2 = withClaims(req2, &auth.Claims{Sub: reactorUsername, Role: "author"})
	w2 := httptest.NewRecorder()
	handlers.ToggleCommentReaction(d)(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second toggle: expected 200, got %d", w2.Code)
	}
	var resp2 struct {
		Counts        map[string]int  `json:"counts"`
		UserReactions map[string]bool `json:"user_reactions"`
	}
	_ = json.NewDecoder(w2.Body).Decode(&resp2)
	if resp2.Counts["fire"] != 0 || resp2.UserReactions["fire"] {
		t.Errorf("expected fire count=0 and user_reactions.fire=false after remove-toggle, got %+v", resp2)
	}
}

// ---------------------------------------------------------------------------
// GetCommentReactions — success
// ---------------------------------------------------------------------------

func TestGetCommentReactions_Success_ReturnsCountsAndViewerState(t *testing.T) {
	d := dbDeps(t)
	authorID, _ := createTestUser(t, d.Pool, "author")
	postID, _ := createTestPost(t, d.Pool, authorID, "published")
	commentID := createTestComment(t, d, postID, authorID, nil)
	viewerID, viewerUsername := createTestUser(t, d.Pool, "author")

	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO comment_reactions (comment_id, user_id, kind) VALUES ($1,$2,'unicorn')`, commentID, viewerID)
	if err != nil {
		t.Fatalf("seed reaction: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/comments/"+commentID+"/reactions", nil)
	req.SetPathValue("id", commentID)
	req = withClaims(req, &auth.Claims{Sub: viewerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetCommentReactions(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Counts        map[string]int  `json:"counts"`
		UserReactions map[string]bool `json:"user_reactions"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Counts["unicorn"] != 1 {
		t.Errorf("expected unicorn count=1, got %+v", resp.Counts)
	}
	if !resp.UserReactions["unicorn"] {
		t.Errorf("expected viewer's own unicorn reaction reflected, got %+v", resp.UserReactions)
	}
}
