package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestBlockUser_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/alice/block", nil)
	w := httptest.NewRecorder()

	handlers.BlockUser(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestBlockUser_BlockerNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/alice/block", nil)
	req.SetPathValue("username", "alice")
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.BlockUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "blocker user not found" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestUnblockUser_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/alice/block", nil)
	w := httptest.NewRecorder()

	handlers.UnblockUser(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestUnblockUser_BlockerNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/alice/block", nil)
	req.SetPathValue("username", "alice")
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnblockUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetBlockStatus_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice/block-status", nil)
	w := httptest.NewRecorder()

	handlers.GetBlockStatus(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestGetBlockStatus_BlockerNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice/block-status", nil)
	req.SetPathValue("username", "alice")
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetBlockStatus(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}
