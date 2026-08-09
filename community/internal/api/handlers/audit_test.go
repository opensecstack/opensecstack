package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestListAuditLog_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-log", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.ListAuditLog(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin (moderator), got %d", w.Code)
	}
}

func TestListAuditLog_NoClaims_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-log", nil)
	w := httptest.NewRecorder()

	handlers.ListAuditLog(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 without claims, got %d", w.Code)
	}
}

func TestListAuditLog_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-log", nil)
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.ListAuditLog(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}
