package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestMuteUser_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/bob/mute", nil)
	w := httptest.NewRecorder()

	handlers.MuteUser(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMuteUser_MuterNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/bob/mute", nil)
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.MuteUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when caller cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestUnmuteUser_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/bob/mute", nil)
	w := httptest.NewRecorder()

	handlers.UnmuteUser(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestUnmuteUser_MuterNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/bob/mute", nil)
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnmuteUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when caller cannot be resolved, got %d", w.Code)
	}
}

func TestGetMuteStatus_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bob/mute", nil)
	w := httptest.NewRecorder()

	handlers.GetMuteStatus(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestGetMuteStatus_MuterNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bob/mute", nil)
	req.SetPathValue("username", "bob")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetMuteStatus(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when caller cannot be resolved, got %d", w.Code)
	}
}

func TestListMutedUsers_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/mutes", nil)
	w := httptest.NewRecorder()

	handlers.ListMutedUsers(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestListMutedUsers_CallerNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/mutes", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListMutedUsers(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when caller cannot be resolved, got %d", w.Code)
	}
}
