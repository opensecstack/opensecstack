package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestDeactivateUser_Success_SetsDeactivatedAt(t *testing.T) {
	d := dbDeps(t)
	_, targetUsername := createTestUser(t, d.Pool, "author")
	_, adminUsername := createTestUser(t, d.Pool, "admin")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUsername+"/deactivate", nil)
	req.SetPathValue("username", targetUsername)
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()

	handlers.DeactivateUser(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
	var deactivated bool
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT deactivated_at IS NOT NULL FROM users WHERE username=$1`, targetUsername).Scan(&deactivated)
	if !deactivated {
		t.Error("expected deactivated_at to be set")
	}
}

func TestDeactivateUser_AlreadyDeactivated_Returns404(t *testing.T) {
	d := dbDeps(t)
	_, targetUsername := createTestUser(t, d.Pool, "author")
	_, adminUsername := createTestUser(t, d.Pool, "admin")

	if _, err := d.Pool.Exec(context.Background(),
		`UPDATE users SET deactivated_at = now() WHERE username=$1`, targetUsername); err != nil {
		t.Fatalf("pre-deactivate: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUsername+"/deactivate", nil)
	req.SetPathValue("username", targetUsername)
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()

	handlers.DeactivateUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for already-deactivated user, got %d", w.Code)
	}
}

func TestReactivateUser_Success_ClearsDeactivatedAt(t *testing.T) {
	d := dbDeps(t)
	_, targetUsername := createTestUser(t, d.Pool, "author")
	_, adminUsername := createTestUser(t, d.Pool, "admin")

	if _, err := d.Pool.Exec(context.Background(),
		`UPDATE users SET deactivated_at = now() WHERE username=$1`, targetUsername); err != nil {
		t.Fatalf("pre-deactivate: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUsername+"/reactivate", nil)
	req.SetPathValue("username", targetUsername)
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()

	handlers.ReactivateUser(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
	var deactivated bool
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT deactivated_at IS NOT NULL FROM users WHERE username=$1`, targetUsername).Scan(&deactivated)
	if deactivated {
		t.Error("expected deactivated_at to be cleared")
	}
}

func TestReactivateUser_NotDeactivated_Returns404(t *testing.T) {
	d := dbDeps(t)
	_, targetUsername := createTestUser(t, d.Pool, "author")
	_, adminUsername := createTestUser(t, d.Pool, "admin")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+targetUsername+"/reactivate", nil)
	req.SetPathValue("username", targetUsername)
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()

	handlers.ReactivateUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for user that is not deactivated, got %d", w.Code)
	}
}

func TestDeactivateUser_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/alice/deactivate", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.DeactivateUser(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestDeactivateUser_NoClaims_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/alice/deactivate", nil)
	w := httptest.NewRecorder()

	handlers.DeactivateUser(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 without claims, got %d", w.Code)
	}
}

func TestDeactivateUser_SelfDeactivate_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/admin/deactivate", nil)
	req.SetPathValue("username", "admin")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.DeactivateUser(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for self-deactivation, got %d", w.Code)
	}
}

func TestDeactivateUser_DBError_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/alice/deactivate", nil)
	req.SetPathValue("username", "alice")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.DeactivateUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on db error, got %d", w.Code)
	}
}

func TestReactivateUser_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/alice/reactivate", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ReactivateUser(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestReactivateUser_DBError_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/alice/reactivate", nil)
	req.SetPathValue("username", "alice")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.ReactivateUser(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on db error, got %d", w.Code)
	}
}
