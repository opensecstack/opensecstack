package handlers_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestAdminListTagAliases_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tags/go/aliases", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.AdminListTagAliases(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestAdminListTagAliases_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tags/go/aliases", nil)
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminListTagAliases(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestAdminCreateTagAlias_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags/go/aliases", bytes.NewReader([]byte(`{"alias":"golang"}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.AdminCreateTagAlias(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestAdminCreateTagAlias_EmptyAlias_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags/go/aliases", bytes.NewReader([]byte(`{"alias":""}`)))
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminCreateTagAlias(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty alias, got %d", w.Code)
	}
}

func TestAdminCreateTagAlias_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags/go/aliases", bytes.NewReader([]byte(`{bad`)))
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminCreateTagAlias(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestAdminCreateTagAlias_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tags/go/aliases", bytes.NewReader([]byte(`{"alias":"golang"}`)))
	req.SetPathValue("slug", "go")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminCreateTagAlias(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestAdminDeleteTagAlias_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/tags/aliases/golang", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.AdminDeleteTagAlias(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestAdminDeleteTagAlias_Admin_Returns204(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/tags/aliases/golang", nil)
	req.SetPathValue("alias", "golang")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.AdminDeleteTagAlias(d)(w, req)

	// The handler ignores the Exec error (best-effort delete), so it always
	// reaches 204 even against an unreachable DB.
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
}
