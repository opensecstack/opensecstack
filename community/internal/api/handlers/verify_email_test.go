package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestVerifyEmail_MissingToken_Returns400(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email", nil)
	w := httptest.NewRecorder()

	handlers.VerifyEmail(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing token, got %d", w.Code)
	}
}

func TestVerifyEmail_InvalidToken_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email?token=bogus", nil)
	w := httptest.NewRecorder()

	handlers.VerifyEmail(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unresolvable token, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestResendVerification_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification", nil)
	w := httptest.NewRecorder()

	handlers.ResendVerification(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestResendVerification_UserNotFound_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ResendVerification(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when user lookup fails, got %d — body: %s", w.Code, w.Body.String())
	}
}
