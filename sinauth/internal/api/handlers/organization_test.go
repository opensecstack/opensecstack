//go:build integration

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/api/middleware"
	"github.com/opensecstack/sinauth/internal/authz"
	"github.com/opensecstack/sinauth/internal/token"
)

// fakeOrgChecker is an in-memory authz.Checker so these tests never need a
// real Permify deployment: Check consults an explicit allow set keyed on
// (subject, permission, entity).
type fakeOrgChecker struct {
	allow map[string]bool
}

func newFakeOrgChecker() *fakeOrgChecker { return &fakeOrgChecker{allow: map[string]bool{}} }

func (f *fakeOrgChecker) key(subject authz.Entity, permission string, entity authz.Entity) string {
	return fmt.Sprintf("%s:%s %s %s:%s", subject.Type, subject.ID, permission, entity.Type, entity.ID)
}

func (f *fakeOrgChecker) allowManage(userID, orgID string) {
	f.allow[f.key(authz.Entity{Type: "user", ID: userID}, "manage", authz.Entity{Type: "organization", ID: orgID})] = true
}

func (f *fakeOrgChecker) Check(_ context.Context, subject authz.Entity, permission string, entity authz.Entity) (bool, error) {
	return f.allow[f.key(subject, permission, entity)], nil
}

func (f *fakeOrgChecker) WriteRelationship(_ context.Context, _ authz.Relationship) error  { return nil }
func (f *fakeOrgChecker) DeleteRelationship(_ context.Context, _ authz.Relationship) error { return nil }

var _ authz.Checker = (*fakeOrgChecker)(nil)

// testDelegationDeps wires a real DB-backed UserSvc/OrgSvc (so platform-admin
// standing and organization membership are authoritative) alongside a fake,
// in-memory authz.Checker standing in for a real, deployed PermifyChecker
// (so the tests don't require a live Permify deployment — see the plan's
// Phase 1 scope, which builds the Checker interface for real but doesn't
// require every test environment to run Permify).
//
// d.Cfg.PermifyEnabled is set true here because this helper simulates
// Permify actually being deployed (the fake checker stands in for
// PermifyChecker). callerCanManageOrg only consults d.Authz.Check when
// PermifyEnabled is true — see TestExploit_SelfServiceOrgRoute_NoopCheckerDoesNotGrantAccess
// below for the PermifyEnabled==false / NoopChecker case, which must NOT go
// through this helper.
func testDelegationDeps(t *testing.T, pool *pgxpool.Pool, checker authz.Checker) Deps {
	t.Helper()
	d := testDeps(t, pool)
	d.Cfg.PermifyEnabled = true
	d.Authz = checker
	return d
}

func bearerCtx(userID string) context.Context {
	return context.WithValue(context.Background(), middleware.ClaimsKey, &token.AccessTokenClaims{Sub: userID})
}

func doOwnMembersRequest(t *testing.T, d Deps, method, path string, ctx context.Context, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.Handle("POST /x/{id}/members", http.HandlerFunc(AddOwnOrganizationMember(d)))
	mux.Handle("DELETE /x/{id}/members/{userId}", http.HandlerFunc(RemoveOwnOrganizationMember(d)))
	mux.ServeHTTP(rec, req)
	return rec
}

// TestAddOwnOrganizationMember_NoClaims_Unauthorized proves a request with no
// bearer claims in context is rejected before any authorization decision.
func TestAddOwnOrganizationMember_NoClaims_Unauthorized(t *testing.T) {
	pool := requireDB(t)
	d := testDelegationDeps(t, pool, newFakeOrgChecker())
	org := createTestOrg(t, d, "private")

	rec := doOwnMembersRequest(t, d, http.MethodPost, "/x/"+org.ID+"/members", context.Background(), `{"user_id":"whoever"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestAddOwnOrganizationMember_NonMemberForbidden proves a caller who is
// neither a platform admin nor granted "manage" on the org by authz.Checker
// is rejected, and the DB is never touched.
func TestAddOwnOrganizationMember_NonMemberForbidden(t *testing.T) {
	pool := requireDB(t)
	checker := newFakeOrgChecker() // allows nothing
	d := testDelegationDeps(t, pool, checker)
	org := createTestOrg(t, d, "private")
	outsider := createTestAuthorizeUser(t, d, fmt.Sprintf("outsider-%d", time.Now().UnixNano()))

	target := fmt.Sprintf(`{"user_id":"%s","org_role":"member"}`, outsider.ID)
	rec := doOwnMembersRequest(t, d, http.MethodPost, "/x/"+org.ID+"/members", bearerCtx(outsider.ID), target)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	members, err := d.OrgSvc.ListMembers(context.Background(), org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("expected zero members after forbidden add, got %+v", members)
	}
}

// TestAddOwnOrganizationMember_OrgOwnerCanManageOwnOrg is the core Phase-1
// deliverable: a caller granted "manage" on this specific org by
// authz.Checker (i.e. an org owner/admin per the Permify schema), who is NOT
// a platform admin, can add a member to THAT org.
func TestAddOwnOrganizationMember_OrgOwnerCanManageOwnOrg(t *testing.T) {
	pool := requireDB(t)
	checker := newFakeOrgChecker()
	d := testDelegationDeps(t, pool, checker)
	org := createTestOrg(t, d, "government")
	owner := createTestAuthorizeUser(t, d, fmt.Sprintf("owner-%d", time.Now().UnixNano()))
	newMember := createTestAuthorizeUser(t, d, fmt.Sprintf("newmember-%d", time.Now().UnixNano()))

	checker.allowManage(owner.ID, org.ID)

	body := fmt.Sprintf(`{"user_id":"%s","org_role":"member"}`, newMember.ID)
	rec := doOwnMembersRequest(t, d, http.MethodPost, "/x/"+org.ID+"/members", bearerCtx(owner.ID), body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	members, err := d.OrgSvc.ListMembers(context.Background(), org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	found := false
	for _, m := range members {
		if m.OrganizationID == org.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected new member in org, got %+v", members)
	}
}

// TestAddOwnOrganizationMember_PlatformAdminAllowedRegardless proves a
// platform admin can still manage ANY organization's members via this route
// even when authz.Checker denies "manage" for that org — the platform-admin
// path is unconditional, mirroring RequireAdmin's existing guarantee.
func TestAddOwnOrganizationMember_PlatformAdminAllowedRegardless(t *testing.T) {
	pool := requireDB(t)
	checker := newFakeOrgChecker() // allows nothing via authz
	d := testDelegationDeps(t, pool, checker)
	org := createTestOrg(t, d, "ngo")
	admin := createTestAuthorizeUser(t, d, fmt.Sprintf("platform-admin-%d", time.Now().UnixNano()))
	newMember := createTestAuthorizeUser(t, d, fmt.Sprintf("newmember2-%d", time.Now().UnixNano()))

	if _, err := d.UserSvc.SetPlatformAdmin(context.Background(), admin.Email, true); err != nil {
		t.Fatalf("SetPlatformAdmin: %v", err)
	}

	body := fmt.Sprintf(`{"user_id":"%s","org_role":"member"}`, newMember.ID)
	rec := doOwnMembersRequest(t, d, http.MethodPost, "/x/"+org.ID+"/members", bearerCtx(admin.ID), body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}
}

// TestRemoveOwnOrganizationMember_OrgOwnerCanManageOwnOrg proves the delete
// side of the same delegation path.
func TestRemoveOwnOrganizationMember_OrgOwnerCanManageOwnOrg(t *testing.T) {
	pool := requireDB(t)
	checker := newFakeOrgChecker()
	d := testDelegationDeps(t, pool, checker)
	org := createTestOrg(t, d, "private")
	owner := createTestAuthorizeUser(t, d, fmt.Sprintf("owner2-%d", time.Now().UnixNano()))
	member := createTestAuthorizeUser(t, d, fmt.Sprintf("member2-%d", time.Now().UnixNano()))
	addTestMember(t, d, org.ID, member.ID, "member")

	checker.allowManage(owner.ID, org.ID)

	rec := doOwnMembersRequest(t, d, http.MethodDelete, "/x/"+org.ID+"/members/"+member.ID, bearerCtx(owner.ID), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	members, err := d.OrgSvc.ListMembers(context.Background(), org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	for _, m := range members {
		if m.OrganizationID == org.ID {
			t.Fatalf("expected member removed, still present: %+v", m)
		}
	}
}

// TestRemoveOwnOrganizationMember_NonMemberForbidden mirrors the add-side
// non-member-forbidden test for the delete route.
func TestRemoveOwnOrganizationMember_NonMemberForbidden(t *testing.T) {
	pool := requireDB(t)
	checker := newFakeOrgChecker()
	d := testDelegationDeps(t, pool, checker)
	org := createTestOrg(t, d, "private")
	outsider := createTestAuthorizeUser(t, d, fmt.Sprintf("outsider2-%d", time.Now().UnixNano()))
	member := createTestAuthorizeUser(t, d, fmt.Sprintf("member3-%d", time.Now().UnixNano()))
	addTestMember(t, d, org.ID, member.ID, "member")

	rec := doOwnMembersRequest(t, d, http.MethodDelete, "/x/"+org.ID+"/members/"+member.ID, bearerCtx(outsider.ID), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestExploit_SelfServiceOrgRoute_NoopCheckerDoesNotGrantAccess reproduces
// the 2026-07-29 privilege-escalation regression: in the actual default
// configuration (SINAUTH_PERMIFY_URL unset, d.Cfg.PermifyEnabled == false),
// authz.New returns a NoopChecker whose Check unconditionally returns
// (true, nil) for ANY subject/entity. Before the fix, callerCanManageOrg
// fell through to d.Authz.Check even when Permify wasn't deployed, so any
// authenticated non-admin user could add themselves as "owner" of an
// arbitrary organization they have no relationship to (or evict its real
// owner via the DELETE route) — org_role is fully attacker-controlled.
//
// This test wires a real authz.NoopChecker (not the fake) with
// d.Cfg.PermifyEnabled explicitly false, mirroring the real default
// deployment, and asserts a non-admin, non-member caller is DENIED when
// attempting to make themselves owner of an org they don't belong to.
func TestExploit_SelfServiceOrgRoute_NoopCheckerDoesNotGrantAccess(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	d.Cfg.PermifyEnabled = false // the real, actual default — Permify not deployed
	d.Authz = authz.NewNoopChecker()

	org := createTestOrg(t, d, "private")
	attacker := createTestAuthorizeUser(t, d, fmt.Sprintf("attacker-%d", time.Now().UnixNano()))

	// Attacker tries to make themselves "owner" of an org they have no
	// relationship to. Under the pre-fix bug, NoopChecker.Check(true, nil)
	// would grant this.
	body := fmt.Sprintf(`{"user_id":"%s","org_role":"owner"}`, attacker.ID)
	rec := doOwnMembersRequest(t, d, http.MethodPost, "/x/"+org.ID+"/members", bearerCtx(attacker.ID), body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("exploit succeeded: status = %d, want %d (body: %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	members, err := d.OrgSvc.ListMembers(context.Background(), org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("exploit succeeded: attacker was added as a member, got %+v", members)
	}

	// Also prove the eviction side of the exploit is blocked: seed a real
	// owner, then have the attacker try to remove them via the DELETE route.
	owner := createTestAuthorizeUser(t, d, fmt.Sprintf("realowner-%d", time.Now().UnixNano()))
	addTestMember(t, d, org.ID, owner.ID, "owner")

	rec2 := doOwnMembersRequest(t, d, http.MethodDelete, "/x/"+org.ID+"/members/"+owner.ID, bearerCtx(attacker.ID), "")
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("exploit succeeded: attacker evicted real owner, status = %d, want %d (body: %s)", rec2.Code, http.StatusForbidden, rec2.Body.String())
	}
	members, err = d.OrgSvc.ListMembers(context.Background(), org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 || members[0].OrgRole != "owner" {
		t.Fatalf("real owner was evicted despite denial, members: %+v", members)
	}
}
