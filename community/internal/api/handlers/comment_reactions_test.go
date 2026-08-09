package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestAddCommentReaction_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/1/reactions", nil)
	w := httptest.NewRecorder()

	handlers.AddCommentReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestAddCommentReaction_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/1/reactions", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.AddCommentReaction(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestRemoveCommentReaction_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/comments/1/reactions", nil)
	w := httptest.NewRecorder()

	handlers.RemoveCommentReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

// RemoveCommentReaction fails open: unresolvable user still returns ok=true.
func TestRemoveCommentReaction_UserNotFound_StillReturnsOK(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/comments/1/reactions", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.RemoveCommentReaction(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (fail-open), got %d", w.Code)
	}
	var resp map[string]bool
	json.NewDecoder(w.Body).Decode(&resp)
	if !resp["ok"] {
		t.Error("expected ok=true")
	}
}

func TestToggleCommentReaction_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/1/reactions/toggle", nil)
	w := httptest.NewRecorder()

	handlers.ToggleCommentReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestToggleCommentReaction_MissingKind_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/1/reactions/toggle", bytes.NewReader([]byte(`{"kind":""}`)))
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ToggleCommentReaction(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing kind, got %d", w.Code)
	}
}

func TestToggleCommentReaction_UserNotFound_Returns401(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/comments/1/reactions/toggle", bytes.NewReader([]byte(`{"kind":"heart"}`)))
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ToggleCommentReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d", w.Code)
	}
}

func TestGetCommentReactions_NoClaims_DBError_ReturnsEmptyCounts(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/comments/1/reactions", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()

	handlers.GetCommentReactions(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Counts        map[string]int  `json:"counts"`
		UserReactions map[string]bool `json:"user_reactions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Counts) != 0 {
		t.Errorf("expected empty counts on db error, got %+v", resp.Counts)
	}
	if len(resp.UserReactions) != 0 {
		t.Errorf("expected empty user_reactions without claims, got %+v", resp.UserReactions)
	}
}
