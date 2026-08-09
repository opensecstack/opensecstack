package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/config"
)

func TestAuthMethods_AllEnabled(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{
		SinauthClientID:   "sinauth-client",
		NativeAuthEnabled: true,
		GitHubClientID:    "gh-client",
		GoogleClientID:    "google-client",
	}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/methods", nil)
	w := httptest.NewRecorder()

	handlers.AuthMethods(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Sinauth        bool `json:"sinauth"`
		SinauthPrimary bool `json:"sinauth_primary"`
		Native         bool `json:"native"`
		GitHub         bool `json:"github"`
		Google         bool `json:"google"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Sinauth || !resp.SinauthPrimary || !resp.Native || !resp.GitHub || !resp.Google {
		t.Errorf("expected all methods enabled, got %+v", resp)
	}
}

func TestAuthMethods_AllDisabled(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/methods", nil)
	w := httptest.NewRecorder()

	handlers.AuthMethods(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Sinauth        bool `json:"sinauth"`
		SinauthPrimary bool `json:"sinauth_primary"`
		Native         bool `json:"native"`
		GitHub         bool `json:"github"`
		Google         bool `json:"google"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Sinauth || resp.SinauthPrimary || resp.Native || resp.GitHub || resp.Google {
		t.Errorf("expected all methods disabled, got %+v", resp)
	}
}
