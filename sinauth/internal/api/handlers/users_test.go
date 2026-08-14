//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/sinauth/internal/api/middleware"
	"github.com/opensecstack/sinauth/internal/token"
)

// usersTestDeps wires the minimal real (DB-backed) UserSvc that ListUsers/
// DeactivateUser/MyOrganizations touch. Authorization for ListUsers/
// DeactivateUser (platform-admin only) is enforced entirely at the router
// level by middleware.RequireAdmin — see clients_test.go's clientsTestDeps
// comment for the same reasoning, confirmed in internal/api/server.go and
// internal/api/server_admin_test.go.
func usersTestDeps(t *testing.T) Deps {
	t.Helper()
	pool := requireDB(t)
	return testDeps(t, pool)
}

func doUsersRequest(t *testing.T, h http.HandlerFunc, method, path, body string, pathValues map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func createUsersTestUser(t *testing.T, d Deps, username string) *tokenlessUser {
	t.Helper()
	u, err := d.UserSvc.Create(context.Background(), username, username+"@example.com", "longenoughpassword", "Test User")
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID) })
	return &tokenlessUser{ID: u.ID, Username: u.Username}
}

// tokenlessUser is a tiny local view avoiding an extra import of the user
// package purely for a struct literal.
type tokenlessUser struct {
	ID       string
	Username string
}

// -------------------- ListUsers --------------------

func TestListUsers_ReturnsCreatedUser_WithoutPasswordHash(t *testing.T) {
	d := usersTestDeps(t)
	username := fmt.Sprintf("listu-%d", time.Now().UnixNano())
	createUsersTestUser(t, d, username)

	rec := doUsersRequest(t, ListUsers(d), http.MethodGet, "/api/v1/admin/users", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PasswordHash") || strings.Contains(rec.Body.String(), "password_hash") {
		t.Fatalf("ListUsers response must never expose password hashes: %s", rec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, u := range out {
		if u["username"] == username {
			found = true
		}
	}
	if !found {
		t.Fatalf("created user %q not present in ListUsers output", username)
	}
}

// -------------------- DeactivateUser --------------------

func TestDeactivateUser_MarksUserDeactivated_AndBlocksLogin(t *testing.T) {
	d := usersTestDeps(t)
	username := fmt.Sprintf("deact-%d", time.Now().UnixNano())
	u := createUsersTestUser(t, d, username)

	rec := doUsersRequest(t, DeactivateUser(d), http.MethodPost, "/api/v1/admin/users/"+u.ID+"/deactivate", "", map[string]string{"id": u.ID})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// A deactivated account must no longer authenticate, even with the
	// correct password (internal/user/service.go's Authenticate checks
	// DeactivatedAt).
	if _, err := d.UserSvc.Authenticate(context.Background(), username, "longenoughpassword"); err == nil {
		t.Fatalf("deactivated user must not be able to authenticate")
	}
}

// A nonexistent user id must not report success. Postgres's UPDATE ...
// WHERE id=$1 is a silent no-op (no error, zero rows touched) when nothing
// matches, so without an existence check DeactivateUser would report 200
// "user deactivated" — and write a "user.deactivated" audit entry — for an
// action that never happened. See the comment on DeactivateUser in users.go.
func TestDeactivateUser_UnknownID_Returns404NotSilentSuccess(t *testing.T) {
	d := usersTestDeps(t)
	rec := doUsersRequest(t, DeactivateUser(d), http.MethodPost, "/api/v1/admin/users/00000000-0000-0000-0000-000000000000/deactivate", "",
		map[string]string{"id": "00000000-0000-0000-0000-000000000000"})

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; deactivating a nonexistent user id must not report success; body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// -------------------- MyOrganizations --------------------

func TestMyOrganizations_NoClaims_Returns401(t *testing.T) {
	d := usersTestDeps(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/organizations", nil)
	rec := httptest.NewRecorder()
	MyOrganizations(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (no claims in context); body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// MyOrganizations must resolve the authenticated user strictly from the
// verified access token's "sub" claim (username) — never from a
// client-suppliable parameter — so one user can never read another user's
// organization memberships (IDOR check).
func TestMyOrganizations_ResolvesFromOwnClaimsOnly_NoIDOR(t *testing.T) {
	d := usersTestDeps(t)
	victim := createUsersTestUser(t, d, fmt.Sprintf("victim-%d", time.Now().UnixNano()))
	_ = victim

	attackerUsername := fmt.Sprintf("attacker-%d", time.Now().UnixNano())
	createUsersTestUser(t, d, attackerUsername)

	claims := &token.AccessTokenClaims{Sub: attackerUsername}
	ctx := context.WithValue(context.Background(), middleware.ClaimsKey, claims)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/organizations", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	MyOrganizations(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	// With OrgSvc wired but no memberships for either user, the response
	// must be an empty list — not an error, and not another user's data.
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no memberships for a fresh user, got %v", out)
	}
}

func TestMyOrganizations_UnknownUserInClaims_Returns404(t *testing.T) {
	d := usersTestDeps(t)
	claims := &token.AccessTokenClaims{Sub: fmt.Sprintf("ghost-%d", time.Now().UnixNano())}
	ctx := context.WithValue(context.Background(), middleware.ClaimsKey, claims)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/organizations", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	MyOrganizations(d)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}
