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

func TestToggleMessageReaction_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/s/channels/c/messages/1/reactions", nil)
	w := httptest.NewRecorder()

	handlers.ToggleMessageReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestToggleMessageReaction_UserNotFound_Returns401(t *testing.T) {
	// resolveUserID fails against the bad DB pool, so userID is "".
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/s/channels/c/messages/1/reactions",
		bytes.NewReader([]byte(`{"emoji":"👍"}`)))
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ToggleMessageReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "user not found" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestRemoveMessageReaction_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/s/channels/c/messages/1/reactions/emoji", nil)
	w := httptest.NewRecorder()

	handlers.RemoveMessageReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestRemoveMessageReaction_UserNotFound_Returns401(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/s/channels/c/messages/1/reactions/emoji", nil)
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req.SetPathValue("id", "1")
	req.SetPathValue("emoji", "👍")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.RemoveMessageReaction(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d", w.Code)
	}
}
