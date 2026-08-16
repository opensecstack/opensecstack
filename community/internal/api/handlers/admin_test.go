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

func TestListAdminUsers_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListAdminUsers(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestListAdminUsers_NoClaims_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	w := httptest.NewRecorder()

	handlers.ListAdminUsers(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 without claims, got %d", w.Code)
	}
}

func TestSetUserRole_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/alice/role", bytes.NewReader([]byte(`{"role":"admin"}`)))
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "viewer"})
	w := httptest.NewRecorder()

	handlers.SetUserRole(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestSetUserRole_CannotChangeOwnRole_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/admin/role", bytes.NewReader([]byte(`{"role":"viewer"}`)))
	req.SetPathValue("username", "admin")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.SetUserRole(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when changing own role, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "cannot change own role" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestSetUserRole_InvalidRole_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/alice/role", bytes.NewReader([]byte(`{"role":"superuser"}`)))
	req.SetPathValue("username", "alice")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.SetUserRole(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid role, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid role" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestSetUserRole_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/alice/role", bytes.NewReader([]byte(`{bad`)))
	req.SetPathValue("username", "alice")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.SetUserRole(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestGetBroadcast_NoActiveBroadcast_ReturnsNullBroadcast(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/broadcasts", nil)
	w := httptest.NewRecorder()

	handlers.GetBroadcast(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["broadcast"] != nil {
		t.Errorf("expected broadcast=nil, got %v", resp["broadcast"])
	}
}

func TestCreateBroadcast_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/broadcasts", bytes.NewReader([]byte(`{"body":"hi"}`)))
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "author"})
	w := httptest.NewRecorder()

	handlers.CreateBroadcast(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestCreateBroadcast_EmptyBody_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/broadcasts", bytes.NewReader([]byte(`{"body":""}`)))
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.CreateBroadcast(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "body is required" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestCreateBroadcast_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/broadcasts", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.CreateBroadcast(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestCreateBroadcast_UnresolvableCaller_Returns500(t *testing.T) {
	// Valid body but the bad DB pool means resolving the caller's ID fails.
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/broadcasts", bytes.NewReader([]byte(`{"body":"hello world"}`)))
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.CreateBroadcast(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when caller cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestDeleteBroadcast_NonAdmin_Returns403(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/broadcasts/1", nil)
	req = withClaims(req, &auth.Claims{Sub: "bob", Role: "viewer"})
	w := httptest.NewRecorder()

	handlers.DeleteBroadcast(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestDeleteBroadcast_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/broadcasts/1", nil)
	req.SetPathValue("id", "1")
	req = withClaims(req, &auth.Claims{Sub: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	handlers.DeleteBroadcast(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

// --- Live-DB success paths ---

func TestListAdminUsers_Success_ReturnsSeededUser(t *testing.T) {
	d := requireLiveDB(t)
	_, targetUsername := seedTestUser(t, d.Pool, "author")
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()

	handlers.ListAdminUsers(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Users []struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"users"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	found := false
	for _, u := range resp.Users {
		if u.Username == targetUsername {
			found = true
			if u.Role != "author" {
				t.Errorf("expected role author, got %q", u.Role)
			}
		}
	}
	if !found {
		t.Error("expected seeded user to appear in admin user list")
	}
}

func TestSetUserRole_Success_UpdatesRole(t *testing.T) {
	d := requireLiveDB(t)
	_, targetUsername := seedTestUser(t, d.Pool, "author")
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/"+targetUsername+"/role", bytes.NewReader([]byte(`{"role":"moderator"}`)))
	req.SetPathValue("username", targetUsername)
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()

	handlers.SetUserRole(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	var role string
	if err := d.Pool.QueryRow(req.Context(), `SELECT role FROM users WHERE username=$1`, targetUsername).Scan(&role); err != nil {
		t.Fatalf("lookup role: %v", err)
	}
	if role != "moderator" {
		t.Errorf("expected role moderator, got %q", role)
	}
}

func TestSetUserRole_UnknownUser_Returns404(t *testing.T) {
	d := requireLiveDB(t)
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/does-not-exist/role", bytes.NewReader([]byte(`{"role":"moderator"}`)))
	req.SetPathValue("username", "does-not-exist")
	req = withClaims(req, &auth.Claims{Sub: adminUsername, Role: "admin"})
	w := httptest.NewRecorder()

	handlers.SetUserRole(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestBroadcastLifecycle_CreateGetDelete(t *testing.T) {
	d := requireLiveDB(t)
	_, adminUsername := seedTestUser(t, d.Pool, "admin")

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/broadcasts", bytes.NewReader([]byte(`{"body":"scheduled maintenance"}`)))
	createReq = withClaims(createReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	createW := httptest.NewRecorder()
	handlers.CreateBroadcast(d)(createW, createReq)
	if createW.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating broadcast, got %d — body: %s", createW.Code, createW.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(createW.Body).Decode(&created)
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(createReq.Context(), `DELETE FROM broadcasts WHERE id=$1`, created.ID)
	})

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/broadcasts", nil)
	getW := httptest.NewRecorder()
	handlers.GetBroadcast(d)(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", getW.Code)
	}
	var getResp struct {
		Broadcast *struct {
			ID string `json:"id"`
		} `json:"broadcast"`
	}
	_ = json.NewDecoder(getW.Body).Decode(&getResp)
	if getResp.Broadcast == nil || getResp.Broadcast.ID != created.ID {
		t.Fatalf("expected active broadcast %q, got %v", created.ID, getResp.Broadcast)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/broadcasts/"+created.ID, nil)
	deleteReq.SetPathValue("id", created.ID)
	deleteReq = withClaims(deleteReq, &auth.Claims{Sub: adminUsername, Role: "admin"})
	deleteW := httptest.NewRecorder()
	handlers.DeleteBroadcast(d)(deleteW, deleteReq)
	if deleteW.Code != http.StatusNoContent {
		t.Fatalf("expected 204 deleting broadcast, got %d", deleteW.Code)
	}

	var active bool
	if err := d.Pool.QueryRow(deleteReq.Context(), `SELECT active FROM broadcasts WHERE id=$1`, created.ID).Scan(&active); err != nil {
		t.Fatalf("lookup broadcast active flag: %v", err)
	}
	if active {
		t.Error("expected broadcast to be deactivated, not deleted")
	}
}
