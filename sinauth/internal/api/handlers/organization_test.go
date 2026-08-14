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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/api/middleware"
	"github.com/opensecstack/sinauth/internal/authz"
	"github.com/opensecstack/sinauth/internal/organization"
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

// --- Admin-route handler tests (ListOrganizations/CreateOrganization/
// GetOrganization/DeleteOrganization/ListOrganizationMembers/
// AddOrganizationMember/RemoveOrganizationMember). These routes are gated
// purely by RequireAdmin at the router level (see server.go and
// server_admin_test.go), so the handler-level tests here call the handlers
// directly (no admin standing check inside the handler itself) and focus on
// input validation, success paths, and cross-organization isolation.

func doAdminOrgRequest(t *testing.T, h http.HandlerFunc, method, path, body string, pathValues map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestCreateOrganization_MissingFields_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)

	rec := doAdminOrgRequest(t, CreateOrganization(d), http.MethodPost, "/admin/organizations", `{"legal_name":"Only Name"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateOrganization_InvalidJSON_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)

	rec := doAdminOrgRequest(t, CreateOrganization(d), http.MethodPost, "/admin/organizations", `{not json`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateOrganization_GetOrganization_ListOrganizations_DeleteOrganization
// exercises the full admin org lifecycle through the handlers.
func TestCreateOrganization_GetOrganization_ListOrganizations_DeleteOrganization(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	slug := fmt.Sprintf("org-%d", time.Now().UnixNano())

	body := fmt.Sprintf(`{"legal_name":"Test Corp","slug":%q,"org_type":"private","registration_number":"RN-1"}`, slug)
	rec := doAdminOrgRequest(t, CreateOrganization(d), http.MethodPost, "/admin/organizations", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d (body: %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var created organization.Organization
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	if created.ID == "" {
		t.Fatalf("expected non-empty id in %+v", created)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, created.ID) })

	getRec := doAdminOrgRequest(t, GetOrganization(d), http.MethodGet, "/admin/organizations/"+created.ID, "", map[string]string{"id": created.ID})
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want %d (body: %s)", getRec.Code, http.StatusOK, getRec.Body.String())
	}
	var fetched organization.Organization
	if err := json.Unmarshal(getRec.Body.Bytes(), &fetched); err != nil {
		t.Fatalf("unmarshal get response: %v", err)
	}
	if fetched.Slug != slug {
		t.Errorf("fetched slug = %q, want %q", fetched.Slug, slug)
	}

	listRec := doAdminOrgRequest(t, ListOrganizations(d), http.MethodGet, "/admin/organizations", "", nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	var orgs []organization.Organization
	if err := json.Unmarshal(listRec.Body.Bytes(), &orgs); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	found := false
	for _, o := range orgs {
		if o.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("created org %s not found in list", created.ID)
	}

	delRec := doAdminOrgRequest(t, DeleteOrganization(d), http.MethodDelete, "/admin/organizations/"+created.ID, "", map[string]string{"id": created.ID})
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d", delRec.Code, http.StatusNoContent)
	}

	getRec2 := doAdminOrgRequest(t, GetOrganization(d), http.MethodGet, "/admin/organizations/"+created.ID, "", map[string]string{"id": created.ID})
	if getRec2.Code != http.StatusNotFound {
		t.Fatalf("get-after-delete status = %d, want %d (body: %s)", getRec2.Code, http.StatusNotFound, getRec2.Body.String())
	}
}

func TestGetOrganization_NotFound(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)

	rec := doAdminOrgRequest(t, GetOrganization(d), http.MethodGet, "/admin/organizations/00000000-0000-0000-0000-000000000000", "",
		map[string]string{"id": "00000000-0000-0000-0000-000000000000"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestAddOrganizationMember_MissingUserID_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	org := createTestOrg(t, d, "private")

	rec := doAdminOrgRequest(t, AddOrganizationMember(d), http.MethodPost, "/admin/organizations/"+org.ID+"/members", `{}`, map[string]string{"id": org.ID})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestAddOrganizationMember_ListOrganizationMembers_RemoveOrganizationMember_
// IsolatedBetweenOrgs exercises the admin-route membership lifecycle and, as
// an IDOR-style check, confirms that listing one organization's members
// never includes a member added to a different organization.
func TestAddOrganizationMember_ListOrganizationMembers_RemoveOrganizationMember_IsolatedBetweenOrgs(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	orgA := createTestOrg(t, d, "private")
	orgB := createTestOrg(t, d, "ngo")
	userA := createTestAuthorizeUser(t, d, fmt.Sprintf("membera-%d", time.Now().UnixNano()))
	userB := createTestAuthorizeUser(t, d, fmt.Sprintf("memberb-%d", time.Now().UnixNano()))

	addRecA := doAdminOrgRequest(t, AddOrganizationMember(d), http.MethodPost, "/admin/organizations/"+orgA.ID+"/members",
		fmt.Sprintf(`{"user_id":%q,"org_role":"member"}`, userA.ID), map[string]string{"id": orgA.ID})
	if addRecA.Code != http.StatusNoContent {
		t.Fatalf("add to orgA status = %d, want %d (body: %s)", addRecA.Code, http.StatusNoContent, addRecA.Body.String())
	}
	addRecB := doAdminOrgRequest(t, AddOrganizationMember(d), http.MethodPost, "/admin/organizations/"+orgB.ID+"/members",
		fmt.Sprintf(`{"user_id":%q,"org_role":"owner"}`, userB.ID), map[string]string{"id": orgB.ID})
	if addRecB.Code != http.StatusNoContent {
		t.Fatalf("add to orgB status = %d, want %d (body: %s)", addRecB.Code, http.StatusNoContent, addRecB.Body.String())
	}

	listRecA := doAdminOrgRequest(t, ListOrganizationMembers(d), http.MethodGet, "/admin/organizations/"+orgA.ID+"/members", "", map[string]string{"id": orgA.ID})
	if listRecA.Code != http.StatusOK {
		t.Fatalf("list orgA status = %d, want %d", listRecA.Code, http.StatusOK)
	}
	var membersA []organization.Membership
	if err := json.Unmarshal(listRecA.Body.Bytes(), &membersA); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(membersA) != 1 || membersA[0].OrganizationID != orgA.ID {
		t.Fatalf("expected exactly userA's membership scoped to orgA, got %+v", membersA)
	}

	// Isolation: orgB's member must not appear in orgA's listing, and
	// vice versa.
	for _, m := range membersA {
		if m.OrganizationID != orgA.ID {
			t.Fatalf("cross-org leak: membership %+v does not belong to orgA %s", m, orgA.ID)
		}
	}

	remRec := doAdminOrgRequest(t, RemoveOrganizationMember(d), http.MethodDelete, "/admin/organizations/"+orgA.ID+"/members/"+userA.ID, "",
		map[string]string{"id": orgA.ID, "userId": userA.ID})
	if remRec.Code != http.StatusNoContent {
		t.Fatalf("remove status = %d, want %d (body: %s)", remRec.Code, http.StatusNoContent, remRec.Body.String())
	}

	listRecA2 := doAdminOrgRequest(t, ListOrganizationMembers(d), http.MethodGet, "/admin/organizations/"+orgA.ID+"/members", "", map[string]string{"id": orgA.ID})
	var membersA2 []organization.Membership
	if err := json.Unmarshal(listRecA2.Body.Bytes(), &membersA2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(membersA2) != 0 {
		t.Fatalf("expected orgA empty after remove, got %+v", membersA2)
	}

	// orgB's membership must be untouched by orgA's removal.
	listRecB := doAdminOrgRequest(t, ListOrganizationMembers(d), http.MethodGet, "/admin/organizations/"+orgB.ID+"/members", "", map[string]string{"id": orgB.ID})
	var membersB []organization.Membership
	if err := json.Unmarshal(listRecB.Body.Bytes(), &membersB); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(membersB) != 1 || membersB[0].OrganizationID != orgB.ID {
		t.Fatalf("expected orgB membership untouched, got %+v", membersB)
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
