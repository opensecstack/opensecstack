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

func TestGenerateInvite_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GenerateInvite(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-moderator, got %d", w.Code)
	}
}

func TestGenerateInvite_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites", nil)
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.GenerateInvite(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

func TestListInvites_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "viewer"})
	w := httptest.NewRecorder()

	handlers.ListInvites(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-moderator, got %d", w.Code)
	}
}

func TestListInvites_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites", nil)
	req = withClaims(req, &auth.Claims{Sub: "mod", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.ListInvites(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

func TestValidateInvite_MissingCode_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites/validate/", nil)
	w := httptest.NewRecorder()

	handlers.ValidateInvite(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing code, got %d", w.Code)
	}
}

func TestValidateInvite_NotFound_ReturnsInvalid(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invites/validate/abc123", nil)
	req.SetPathValue("code", "abc123")
	w := httptest.NewRecorder()

	handlers.ValidateInvite(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if valid, _ := resp["valid"].(bool); valid {
		t.Error("expected valid=false for unknown code")
	}
	if resp["reason"] != "not found" {
		t.Errorf("expected reason='not found', got %v", resp["reason"])
	}
}
