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

func TestListChannelMessages_ChannelNotFound_Returns404(t *testing.T) {
	// No claims required — public endpoint. resolveChannel fails against the
	// bad DB pool, so the channel lookup returns not-found.
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/s/channels/c/messages", nil)
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	w := httptest.NewRecorder()

	handlers.ListChannelMessages(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "channel not found" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestCreateChannelMessage_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/s/channels/c/messages", nil)
	w := httptest.NewRecorder()

	handlers.CreateChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestCreateChannelMessage_UserNotFound_Returns401(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/s/channels/c/messages",
		bytes.NewReader([]byte(`{"content":"hello"}`)))
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d", w.Code)
	}
}

func TestEditChannelMessage_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/s/channels/c/messages/1", nil)
	w := httptest.NewRecorder()

	handlers.EditChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestEditChannelMessage_UserNotFound_Returns401(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/spaces/s/channels/c/messages/1",
		bytes.NewReader([]byte(`{"content":"edited"}`)))
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.EditChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d", w.Code)
	}
}

func TestDeleteChannelMessage_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/s/channels/c/messages/1", nil)
	w := httptest.NewRecorder()

	handlers.DeleteChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestDeleteChannelMessage_UserNotFound_Returns401(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/spaces/s/channels/c/messages/1", nil)
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.DeleteChannelMessage(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when user cannot be resolved, got %d", w.Code)
	}
}
