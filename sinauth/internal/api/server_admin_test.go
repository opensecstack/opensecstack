//go:build integration

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/config"
	"github.com/opensecstack/sinauth/internal/keys"
	"github.com/opensecstack/sinauth/internal/organization"
	"github.com/opensecstack/sinauth/internal/token"
	"github.com/opensecstack/sinauth/internal/user"
)

// This file proves, end-to-end against the real router (api.NewServer),
// that the vulnerability described in the 2026-07-26 security review is
// closed: /admin/organizations/* and /admin/rbac/groups/* now require
// platform-admin standing, not just a validly-signed token, and the
// concrete self-escalation exploit (granting yourself org_role=owner in an
// organization you were never a member of) no longer works.
//
// TestRemainingAdminRoutes_RequireAdmin (2026-07-27 fast-follow) extends the
// same proof to every other /admin/* route group that shared the identical
// BearerAuth-only gap: OAuth client management, user management, audit log,
// sessions, federation providers, and RBAC client-roles/policies. See
// SECURITY.md and adrs/005-organization-identity.md.

func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("SINAUTH_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping api server integration test")
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

const testIssuer = "https://sinauth.test"

// testServer builds a real api.NewServer instance backed by the test DB and
// a throwaway signing key, returning the handler plus an Issuer sharing
// that key so tests can mint tokens the server's Verifier will accept.
func testServer(t *testing.T, pool *pgxpool.Pool) (http.Handler, *token.Issuer) {
	t.Helper()
	km := keys.New("test-kid")
	keyPath := filepath.Join(t.TempDir(), "sinauth.pem")
	if err := km.LoadOrGenerate(keyPath); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	cfg := &config.Config{
		Issuer:                testIssuer,
		BcryptCost:            4,
		WebAuthnRPID:          "localhost",
		WebAuthnRPDisplayName: "sinauth-test",
		WebAuthnOrigins:       []string{"http://localhost"},
		RateLimitAuthPerMin:   100000,
		RateLimitGlobalPerMin: 100000,
	}
	handler := NewServer(cfg, pool, km)
	issuer := token.NewIssuer(km.PrivateKey(), km.KeyID(), testIssuer)
	return handler, issuer
}

func createUser(t *testing.T, pool *pgxpool.Pool, username string) *user.User {
	t.Helper()
	store := user.NewStore(pool)
	u := &user.User{Username: username, Email: username + "@example.com"}
	if err := store.Create(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID) })
	return u
}

func promoteToAdmin(t *testing.T, pool *pgxpool.Pool, email string) {
	t.Helper()
	store := user.NewStore(pool)
	found, err := store.SetPlatformAdmin(context.Background(), email, true)
	if err != nil {
		t.Fatalf("SetPlatformAdmin: %v", err)
	}
	if !found {
		t.Fatal("SetPlatformAdmin: user not found")
	}
}

func bearerRequest(t *testing.T, handler http.Handler, method, path, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestAdminOrganizations_NonAdminForbidden_AdminAllowed proves the fix for
// route group 1 named in the audit: /admin/organizations/*.
func TestAdminOrganizations_NonAdminForbidden_AdminAllowed(t *testing.T) {
	pool := requireDB(t)
	handler, issuer := testServer(t, pool)

	plain := createUser(t, pool, fmt.Sprintf("plain-org-%d", time.Now().UnixNano()))
	admin := createUser(t, pool, fmt.Sprintf("admin-org-%d", time.Now().UnixNano()))
	promoteToAdmin(t, pool, admin.Email)

	plainTok, err := issuer.IssueAccessToken(plain.ID, "sinauth", nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken plain: %v", err)
	}
	adminTok, err := issuer.IssueAccessToken(admin.ID, "sinauth", nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken admin: %v", err)
	}

	// A non-admin authenticated user must be rejected with 403.
	rec := bearerRequest(t, handler, http.MethodGet, "/admin/organizations", plainTok, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin GET /admin/organizations: status=%d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}

	// An unauthenticated caller must be rejected with 401.
	rec = bearerRequest(t, handler, http.MethodGet, "/admin/organizations", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-token GET /admin/organizations: status=%d, want 401", rec.Code)
	}

	// A real platform admin must succeed.
	rec = bearerRequest(t, handler, http.MethodGet, "/admin/organizations", adminTok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin GET /admin/organizations: status=%d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestAdminRBACGroups_NonAdminForbidden_AdminAllowed proves the fix for
// route group 2 named in the audit: /admin/rbac/groups/*.
func TestAdminRBACGroups_NonAdminForbidden_AdminAllowed(t *testing.T) {
	pool := requireDB(t)
	handler, issuer := testServer(t, pool)

	plain := createUser(t, pool, fmt.Sprintf("plain-rbac-%d", time.Now().UnixNano()))
	admin := createUser(t, pool, fmt.Sprintf("admin-rbac-%d", time.Now().UnixNano()))
	promoteToAdmin(t, pool, admin.Email)

	plainTok, _ := issuer.IssueAccessToken(plain.ID, "sinauth", nil, time.Hour)
	adminTok, _ := issuer.IssueAccessToken(admin.ID, "sinauth", nil, time.Hour)

	rec := bearerRequest(t, handler, http.MethodGet, "/admin/rbac/groups", plainTok, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin GET /admin/rbac/groups: status=%d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}

	rec = bearerRequest(t, handler, http.MethodGet, "/admin/rbac/groups", adminTok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin GET /admin/rbac/groups: status=%d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	// A non-admin cannot create groups either — POST is gated the same way.
	rec = bearerRequest(t, handler, http.MethodPost, "/admin/rbac/groups", plainTok, `{"name":"pwned"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin POST /admin/rbac/groups: status=%d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestExploit_SelfGrantOrgOwnership_NoLongerWorks reproduces the exact
// exploit scenario from the security review: an authenticated user with no
// standing in an organization calls POST /admin/organizations/{id}/members
// with {"user_id": <self>, "org_role": "owner"} to self-escalate. Before
// this fix, BearerAuth alone let this through and organization.AddMember
// accepted the attacker-supplied role unconditionally. It must now be
// rejected with 403 before the handler — and org.AddMember/GetOrganization
// prove the DB was never touched.
func TestExploit_SelfGrantOrgOwnership_NoLongerWorks(t *testing.T) {
	pool := requireDB(t)
	handler, issuer := testServer(t, pool)
	ctx := context.Background()

	attacker := createUser(t, pool, fmt.Sprintf("attacker-%d", time.Now().UnixNano()))
	attackerTok, err := issuer.IssueAccessToken(attacker.ID, "sinauth", nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	orgStore := organization.NewStore(pool)
	org, err := orgStore.Create(ctx, organization.Organization{
		LegalName: "Victim Org",
		Slug:      fmt.Sprintf("victim-org-%d", time.Now().UnixNano()),
		OrgType:   "private",
	})
	if err != nil {
		t.Fatalf("create victim org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID) })

	body := fmt.Sprintf(`{"user_id":"%s","org_role":"owner"}`, attacker.ID)
	rec := bearerRequest(t, handler, http.MethodPost, "/admin/organizations/"+org.ID+"/members", attackerTok, body)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("self-escalation attempt: status=%d, want 403 (body: %s) — exploit NOT closed", rec.Code, rec.Body.String())
	}

	members, err := orgStore.ListMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("expected zero members after rejected self-escalation, got %+v — exploit NOT closed", members)
	}
}

// TestRemainingAdminRoutes_RequireAdmin is the 2026-07-27 fast-follow proof:
// every other /admin/* route group that previously relied on plain
// BearerAuth now requires platform-admin standing too. For each route this
// checks that a non-admin authenticated caller is rejected with 403 and,
// for the simple list endpoints, that a real platform admin still succeeds.
func TestRemainingAdminRoutes_RequireAdmin(t *testing.T) {
	pool := requireDB(t)
	handler, issuer := testServer(t, pool)

	plain := createUser(t, pool, fmt.Sprintf("plain-remaining-%d", time.Now().UnixNano()))
	admin := createUser(t, pool, fmt.Sprintf("admin-remaining-%d", time.Now().UnixNano()))
	promoteToAdmin(t, pool, admin.Email)

	plainTok, err := issuer.IssueAccessToken(plain.ID, "sinauth", nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken plain: %v", err)
	}
	adminTok, err := issuer.IssueAccessToken(admin.ID, "sinauth", nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken admin: %v", err)
	}

	// Simple list endpoints: non-admin must get 403, admin must get 200.
	listRoutes := []string{
		"/api/v1/admin/clients",
		"/api/v1/admin/users",
		"/api/v1/admin/audit",
		"/api/v1/admin/sessions",
		"/admin/rbac/policies",
	}
	for _, path := range listRoutes {
		rec := bearerRequest(t, handler, http.MethodGet, path, plainTok, "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("non-admin GET %s: status=%d, want 403 (body: %s)", path, rec.Code, rec.Body.String())
		}

		rec = bearerRequest(t, handler, http.MethodGet, path, adminTok, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("admin GET %s: status=%d, want 200 (body: %s)", path, rec.Code, rec.Body.String())
		}
	}

	// Write/param routes: a non-admin caller must be rejected with 403
	// before the handler ever sees the request, regardless of whether the
	// referenced resource exists.
	writeRoutes := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/admin/clients", `{"client_id":"pwned","grant_types":["authorization_code"]}`},
		{http.MethodDelete, "/api/v1/admin/clients/does-not-exist", ""},
		{http.MethodPost, "/api/v1/admin/users/does-not-exist/deactivate", ""},
		{http.MethodDelete, "/api/v1/admin/sessions/does-not-exist", ""},
		{http.MethodPost, "/admin/federation/providers", `{"slug":"pwned"}`},
		{http.MethodDelete, "/admin/federation/providers/does-not-exist", ""},
		{http.MethodGet, "/admin/rbac/clients/does-not-exist/roles", ""},
		{http.MethodPost, "/admin/rbac/clients/does-not-exist/roles", `{"role_name":"pwned"}`},
		{http.MethodDelete, "/admin/rbac/roles/does-not-exist", ""},
		{http.MethodPost, "/admin/rbac/users/does-not-exist/roles", `{"role_name":"pwned"}`},
		{http.MethodDelete, "/admin/rbac/users/does-not-exist/roles", ""},
		{http.MethodGet, "/admin/rbac/users/does-not-exist/effective-roles", ""},
		{http.MethodPost, "/admin/rbac/policies", `{"name":"pwned"}`},
		{http.MethodDelete, "/admin/rbac/policies/does-not-exist", ""},
	}
	for _, wr := range writeRoutes {
		rec := bearerRequest(t, handler, wr.method, wr.path, plainTok, wr.body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("non-admin %s %s: status=%d, want 403 (body: %s)", wr.method, wr.path, rec.Code, rec.Body.String())
		}
	}

	// Unauthenticated callers must be rejected with 401, not 403 — proves
	// RequireAdmin still runs BearerAuth first.
	rec := bearerRequest(t, handler, http.MethodGet, "/api/v1/admin/users", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-token GET /api/v1/admin/users: status=%d, want 401", rec.Code)
	}
}
