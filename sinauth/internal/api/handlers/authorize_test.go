//go:build integration

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/client"
	"github.com/opensecstack/sinauth/internal/config"
	"github.com/opensecstack/sinauth/internal/organization"
	"github.com/opensecstack/sinauth/internal/user"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used in internal/organization/store_test.go
// and elsewhere in the ecosystem (e.g. vertguard/internal/ioc/store_test.go).
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("SINAUTH_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping authorize handler integration test")
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// testDeps wires the minimal set of real (DB-backed) services AuthorizePOST
// touches: user auth, client validation, and org membership resolution.
func testDeps(t *testing.T, pool *pgxpool.Pool) Deps {
	t.Helper()
	return Deps{
		Pool:      pool,
		Cfg:       &config.Config{SiteURL: "https://sinauth.test", BcryptCost: 4},
		ClientSvc: client.NewService(client.NewStore(pool)),
		UserSvc:   user.NewService(user.NewStore(pool), 4),
		OrgSvc:    organization.NewStore(pool),
	}
}

const testPassword = "correct horse battery staple"

func createTestOAuthClient(t *testing.T, d Deps, redirectURI string) string {
	t.Helper()
	clientID := fmt.Sprintf("test-client-%d", time.Now().UnixNano())
	c := &client.Client{
		ClientID:      clientID,
		Name:          "Test Client",
		RedirectURIs:  []string{redirectURI},
		AllowedScopes: []string{"openid", "profile"},
		GrantTypes:    []string{"authorization_code"},
		RequirePKCE:   false,
	}
	if err := d.ClientSvc.Create(context.Background(), c); err != nil {
		t.Fatalf("create test client: %v", err)
	}
	t.Cleanup(func() { _ = d.ClientSvc.Delete(context.Background(), clientID) })
	return clientID
}

func createTestAuthorizeUser(t *testing.T, d Deps, username string) *user.User {
	t.Helper()
	u, err := d.UserSvc.Create(context.Background(), username, username+"@example.com", testPassword, "Test User")
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID) })
	return u
}

func createTestOrg(t *testing.T, d Deps, orgType string) organization.Organization {
	t.Helper()
	slug := fmt.Sprintf("test-org-%d", time.Now().UnixNano())
	org, err := d.OrgSvc.Create(context.Background(), organization.Organization{
		LegalName: "Test Org " + slug,
		Slug:      slug,
		OrgType:   orgType,
	})
	if err != nil {
		t.Fatalf("create test org: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org.ID) })
	return org
}

func addTestMember(t *testing.T, d Deps, orgID, userID, role string) {
	t.Helper()
	if err := d.OrgSvc.AddMember(context.Background(), orgID, userID, role); err != nil {
		t.Fatalf("add member: %v", err)
	}
}

func doAuthorizePOST(t *testing.T, d Deps, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize?"+form.Encode(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	AuthorizePOST(d)(rec, req)
	return rec
}

func baseForm(username, clientID, redirectURI string) url.Values {
	return url.Values{
		"username":     {username},
		"password":     {testPassword},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
		"scope":        {"openid profile"},
		"state":        {"xyz"},
	}
}

// 0 memberships: unchanged pure-individual flow — a code is issued directly.
func TestAuthorizePOST_ZeroMemberships_Unchanged(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("zero-mem-%d", time.Now().UnixNano()))

	rec := doAuthorizePOST(t, d, baseForm(u.Username, clientID, redirectURI))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "code=") {
		t.Fatalf("Location = %q, expected a code param", loc)
	}
	if strings.Contains(loc, "org-picker") {
		t.Fatalf("Location = %q, should not redirect to org-picker with zero memberships", loc)
	}
}

// Exactly 1 membership + no organization_id: per ADR 005 "never guess",
// sinauth does NOT auto-select the user's sole organization. It behaves
// exactly like the zero-membership case — a code is issued with no org
// context, not a picker redirect. An org-aware client that wants org claims
// must always pass organization_id explicitly, regardless of how many
// organizations are available to choose from.
func TestAuthorizePOST_OneMembership_NoParam_ProceedsWithoutOrgContext(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("one-mem-%d", time.Now().UnixNano()))
	org := createTestOrg(t, d, "private")
	addTestMember(t, d, org.ID, u.ID, "member")

	rec := doAuthorizePOST(t, d, baseForm(u.Username, clientID, redirectURI))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "org-picker") {
		t.Fatalf("Location = %q, single membership must not trigger the org picker", loc)
	}
	if !strings.Contains(loc, "code=") {
		t.Fatalf("Location = %q, expected a code param", loc)
	}
}

// 2+ memberships + a valid, member-validated organization_id: the code is
// issued carrying that organization context.
func TestAuthorizePOST_MultiMembership_WithValidOrgID_IssuesScopedCode(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("multi-mem-%d", time.Now().UnixNano()))
	orgA := createTestOrg(t, d, "government")
	orgB := createTestOrg(t, d, "ngo")
	addTestMember(t, d, orgA.ID, u.ID, "owner")
	addTestMember(t, d, orgB.ID, u.ID, "member")

	form := baseForm(u.Username, clientID, redirectURI)
	form.Set("organization_id", orgA.ID)
	rec := doAuthorizePOST(t, d, form)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("Location = %q, expected a code param", loc)
	}

	var storedOrgID string
	err = pool.QueryRow(context.Background(),
		`SELECT organization_id::text FROM authorization_codes WHERE code=$1`, code,
	).Scan(&storedOrgID)
	if err != nil {
		t.Fatalf("query stored code: %v", err)
	}
	if storedOrgID != orgA.ID {
		t.Errorf("stored organization_id = %q, want %q", storedOrgID, orgA.ID)
	}
}

// 2+ memberships + no organization_id: sinauth refuses to guess and sends
// the user to the org picker instead of issuing a code.
func TestAuthorizePOST_MultiMembership_NoOrgID_RedirectsToPicker(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("multi-mem-nopick-%d", time.Now().UnixNano()))
	orgA := createTestOrg(t, d, "government")
	orgB := createTestOrg(t, d, "ecommerce")
	addTestMember(t, d, orgA.ID, u.ID, "owner")
	addTestMember(t, d, orgB.ID, u.ID, "member")

	form := baseForm(u.Username, clientID, redirectURI)
	rec := doAuthorizePOST(t, d, form)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/oauth/org-picker") {
		t.Fatalf("Location = %q, expected redirect to /oauth/org-picker", loc)
	}
	if strings.Contains(loc, "code=") {
		t.Fatalf("Location = %q, no code should be issued when the picker is required", loc)
	}
}

// An organization_id the user is NOT a member of must be rejected — sinauth
// never trusts the caller-supplied value blindly.
func TestAuthorizePOST_InvalidOrgID_Forbidden(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("not-a-member-%d", time.Now().UnixNano()))
	// org exists, but u is never added as a member of it.
	foreignOrg := createTestOrg(t, d, "private")

	form := baseForm(u.Username, clientID, redirectURI)
	form.Set("organization_id", foreignOrg.ID)
	rec := doAuthorizePOST(t, d, form)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}
