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

	"github.com/opensecstack/sinauth/internal/rbac"
)

// testRBACDeps wires a real DB-backed rbac.Store on top of the base testDeps
// (see authorize_test.go), mirroring testTokenDeps in token_test.go.
func testRBACDeps(t *testing.T, pool *pgxpool.Pool) Deps {
	t.Helper()
	d := testDeps(t, pool)
	d.RBAC = rbac.NewStore(pool)
	return d
}

func doRBACRequest(t *testing.T, h http.HandlerFunc, method, path, body string, pathValues map[string]string) *httptest.ResponseRecorder {
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

func cleanupGroup(t *testing.T, d Deps, id string) {
	t.Helper()
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM groups WHERE id=$1`, id) })
}

func cleanupClientRole(t *testing.T, d Deps, id string) {
	t.Helper()
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM client_roles WHERE id=$1`, id) })
}

func cleanupPolicy(t *testing.T, d Deps, id string) {
	t.Helper()
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM policies WHERE id=$1`, id) })
}

// --- Group handlers ---

func TestCreateGroup_MissingName_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)

	rec := doRBACRequest(t, CreateGroup(d), http.MethodPost, "/admin/rbac/groups", `{"description":"no name"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateGroup_InvalidJSON_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)

	rec := doRBACRequest(t, CreateGroup(d), http.MethodPost, "/admin/rbac/groups", `{not json`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateGroup_UnknownField_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)

	// decodeJSON uses DisallowUnknownFields, so an unexpected field is
	// rejected rather than silently ignored.
	rec := doRBACRequest(t, CreateGroup(d), http.MethodPost, "/admin/rbac/groups", `{"name":"g","unexpected":"x"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroup_ListGroup_DeleteGroup exercises the full group lifecycle
// through the handlers: create returns an id, the group shows up in
// ListGroups, and DeleteGroup removes it again.
func TestCreateGroup_ListGroup_DeleteGroup(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	name := fmt.Sprintf("group-%d", time.Now().UnixNano())

	rec := doRBACRequest(t, CreateGroup(d), http.MethodPost, "/admin/rbac/groups",
		fmt.Sprintf(`{"name":%q,"description":"test group"}`, name), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d (body: %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var created map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	id := created["id"]
	if id == "" {
		t.Fatalf("expected non-empty id in %v", created)
	}
	cleanupGroup(t, d, id)

	listRec := doRBACRequest(t, ListGroups(d), http.MethodGet, "/admin/rbac/groups", "", nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	var groups []rbac.Group
	if err := json.Unmarshal(listRec.Body.Bytes(), &groups); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	found := false
	for _, g := range groups {
		if g.ID == id {
			found = true
			if g.Name != name {
				t.Errorf("group name = %q, want %q", g.Name, name)
			}
		}
	}
	if !found {
		t.Fatalf("created group %s not found in list %+v", id, groups)
	}

	delRec := doRBACRequest(t, DeleteGroup(d), http.MethodDelete, "/admin/rbac/groups/"+id, "", map[string]string{"id": id})
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d", delRec.Code, http.StatusNoContent)
	}

	listRec2 := doRBACRequest(t, ListGroups(d), http.MethodGet, "/admin/rbac/groups", "", nil)
	var groups2 []rbac.Group
	if err := json.Unmarshal(listRec2.Body.Bytes(), &groups2); err != nil {
		t.Fatalf("unmarshal second list response: %v", err)
	}
	for _, g := range groups2 {
		if g.ID == id {
			t.Fatalf("group %s still present after delete", id)
		}
	}
}

func createTestGroup(t *testing.T, d Deps, name string) string {
	t.Helper()
	id, err := d.RBAC.CreateGroup(context.Background(), name, "")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	cleanupGroup(t, d, id)
	return id
}

func TestAddGroupMember_MissingUserID_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	groupID := createTestGroup(t, d, fmt.Sprintf("g-%d", time.Now().UnixNano()))

	rec := doRBACRequest(t, AddGroupMember(d), http.MethodPost, "/admin/rbac/groups/"+groupID+"/members", `{}`, map[string]string{"id": groupID})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestAddGroupMember_ListMembers_RemoveGroupMember exercises the membership
// lifecycle end-to-end and confirms ListGroupMembers reflects add/remove.
func TestAddGroupMember_ListMembers_RemoveGroupMember(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	groupID := createTestGroup(t, d, fmt.Sprintf("g-%d", time.Now().UnixNano()))
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("groupmember-%d", time.Now().UnixNano()))

	addRec := doRBACRequest(t, AddGroupMember(d), http.MethodPost, "/admin/rbac/groups/"+groupID+"/members",
		fmt.Sprintf(`{"user_id":%q}`, u.ID), map[string]string{"id": groupID})
	if addRec.Code != http.StatusNoContent {
		t.Fatalf("add status = %d, want %d (body: %s)", addRec.Code, http.StatusNoContent, addRec.Body.String())
	}

	listRec := doRBACRequest(t, ListGroupMembers(d), http.MethodGet, "/admin/rbac/groups/"+groupID+"/members", "", map[string]string{"id": groupID})
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	var members []string
	if err := json.Unmarshal(listRec.Body.Bytes(), &members); err != nil {
		t.Fatalf("unmarshal members: %v", err)
	}
	found := false
	for _, m := range members {
		if m == u.Username {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %s in members %+v", u.Username, members)
	}

	remRec := doRBACRequest(t, RemoveGroupMember(d), http.MethodDelete, "/admin/rbac/groups/"+groupID+"/members/"+u.ID, "",
		map[string]string{"id": groupID, "userId": u.ID})
	if remRec.Code != http.StatusNoContent {
		t.Fatalf("remove status = %d, want %d (body: %s)", remRec.Code, http.StatusNoContent, remRec.Body.String())
	}

	listRec2 := doRBACRequest(t, ListGroupMembers(d), http.MethodGet, "/admin/rbac/groups/"+groupID+"/members", "", map[string]string{"id": groupID})
	var members2 []string
	if err := json.Unmarshal(listRec2.Body.Bytes(), &members2); err != nil {
		t.Fatalf("unmarshal members after remove: %v", err)
	}
	for _, m := range members2 {
		if m == u.Username {
			t.Fatalf("expected %s removed, still present in %+v", u.Username, members2)
		}
	}
}

// --- Client Role handlers ---

func TestCreateClientRole_MissingName_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)

	rec := doRBACRequest(t, CreateClientRole(d), http.MethodPost, "/admin/rbac/clients/c1/roles", `{"description":"x"}`, map[string]string{"clientId": "c1"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateClientRole_Success exercises the CreateClientRole handler
// itself (as opposed to createTestClientRole's direct store call used by
// other tests below), confirming it returns 201 with an id and that the
// role becomes visible via ListClientRoles scoped to that client.
func TestCreateClientRole_Success(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	clientID := fmt.Sprintf("client-create-%d", time.Now().UnixNano())

	rec := doRBACRequest(t, CreateClientRole(d), http.MethodPost, "/admin/rbac/clients/"+clientID+"/roles",
		`{"name":"analyst","description":"read-only analyst"}`, map[string]string{"clientId": clientID})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var created map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	id := created["id"]
	if id == "" {
		t.Fatalf("expected non-empty id in %v", created)
	}
	cleanupClientRole(t, d, id)

	roles, err := d.RBAC.ListClientRoles(context.Background(), clientID)
	if err != nil {
		t.Fatalf("ListClientRoles: %v", err)
	}
	found := false
	for _, r := range roles {
		if r.ID == id && r.Name == "analyst" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected created role in %+v", roles)
	}
}

func createTestClientRole(t *testing.T, d Deps, clientID, name string) string {
	t.Helper()
	id, err := d.RBAC.CreateClientRole(context.Background(), clientID, name, "")
	if err != nil {
		t.Fatalf("CreateClientRole: %v", err)
	}
	cleanupClientRole(t, d, id)
	return id
}

// TestListClientRoles_ScopedPerClient is an isolation/IDOR-style check:
// roles created for one OAuth client must never leak into another client's
// role listing.
func TestListClientRoles_ScopedPerClient(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	clientA := fmt.Sprintf("client-a-%d", time.Now().UnixNano())
	clientB := fmt.Sprintf("client-b-%d", time.Now().UnixNano())

	roleA := createTestClientRole(t, d, clientA, "analyst")
	_ = createTestClientRole(t, d, clientB, "viewer")

	recA := doRBACRequest(t, ListClientRoles(d), http.MethodGet, "/admin/rbac/clients/"+clientA+"/roles", "", map[string]string{"clientId": clientA})
	if recA.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recA.Code, http.StatusOK)
	}
	var rolesA []rbac.ClientRole
	if err := json.Unmarshal(recA.Body.Bytes(), &rolesA); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rolesA) != 1 || rolesA[0].ID != roleA {
		t.Fatalf("expected exactly role %s scoped to client %s, got %+v", roleA, clientA, rolesA)
	}
	for _, r := range rolesA {
		if r.ClientID != clientA {
			t.Fatalf("cross-client leak: role %+v does not belong to %s", r, clientA)
		}
	}
}

func TestDeleteClientRole(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	clientID := fmt.Sprintf("client-%d", time.Now().UnixNano())
	roleID := createTestClientRole(t, d, clientID, "temp-role")

	rec := doRBACRequest(t, DeleteClientRole(d), http.MethodDelete, "/admin/rbac/roles/"+roleID, "", map[string]string{"id": roleID})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	roles, err := d.RBAC.ListClientRoles(context.Background(), clientID)
	if err != nil {
		t.Fatalf("ListClientRoles: %v", err)
	}
	for _, r := range roles {
		if r.ID == roleID {
			t.Fatalf("role %s still present after delete", roleID)
		}
	}
}

// --- User role assignment handlers ---

func TestAssignUserRole_MissingFields_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("assignuser-%d", time.Now().UnixNano()))

	rec := doRBACRequest(t, AssignUserRole(d), http.MethodPost, "/admin/rbac/users/"+u.ID+"/roles", `{}`, map[string]string{"userId": u.ID})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestAssignUserRole_GetUserEffectiveRoles_RevokeUserRole exercises the
// full role-grant lifecycle and confirms effective-roles reflects both
// direct and (via group) inherited assignments, plus scoping by client_id.
func TestAssignUserRole_GetUserEffectiveRoles_RevokeUserRole(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	clientID := fmt.Sprintf("client-%d", time.Now().UnixNano())
	otherClientID := fmt.Sprintf("client-other-%d", time.Now().UnixNano())
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("effroles-%d", time.Now().UnixNano()))
	createTestClientRole(t, d, clientID, "editor")

	assignRec := doRBACRequest(t, AssignUserRole(d), http.MethodPost, "/admin/rbac/users/"+u.ID+"/roles",
		fmt.Sprintf(`{"client_id":%q,"role_name":"editor"}`, clientID), map[string]string{"userId": u.ID})
	if assignRec.Code != http.StatusNoContent {
		t.Fatalf("assign status = %d, want %d (body: %s)", assignRec.Code, http.StatusNoContent, assignRec.Body.String())
	}

	// GetUserEffectiveRoles requires client_id.
	noClientRec := doRBACRequest(t, GetUserEffectiveRoles(d), http.MethodGet, "/admin/rbac/users/"+u.ID+"/effective-roles", "", map[string]string{"userId": u.ID})
	if noClientRec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", noClientRec.Code, http.StatusBadRequest, noClientRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/rbac/users/"+u.ID+"/effective-roles?client_id="+clientID, nil)
	req.SetPathValue("userId", u.ID)
	rec := httptest.NewRecorder()
	GetUserEffectiveRoles(d)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string][]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	roles := resp["roles"]
	if len(roles) != 1 || roles[0] != "editor" {
		t.Fatalf("expected [editor], got %+v", roles)
	}

	// Isolation check: the user's roles must not leak into an unrelated
	// client's effective-roles lookup.
	req2 := httptest.NewRequest(http.MethodGet, "/admin/rbac/users/"+u.ID+"/effective-roles?client_id="+otherClientID, nil)
	req2.SetPathValue("userId", u.ID)
	rec2 := httptest.NewRecorder()
	GetUserEffectiveRoles(d)(rec2, req2)
	var resp2 map[string][]string
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp2["roles"]) != 0 {
		t.Fatalf("expected no roles for unrelated client, got %+v", resp2["roles"])
	}

	revokeRec := doRBACRequest(t, RevokeUserRole(d), http.MethodDelete, "/admin/rbac/users/"+u.ID+"/roles",
		fmt.Sprintf(`{"client_id":%q,"role_name":"editor"}`, clientID), map[string]string{"userId": u.ID})
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d (body: %s)", revokeRec.Code, http.StatusNoContent, revokeRec.Body.String())
	}

	req3 := httptest.NewRequest(http.MethodGet, "/admin/rbac/users/"+u.ID+"/effective-roles?client_id="+clientID, nil)
	req3.SetPathValue("userId", u.ID)
	rec3 := httptest.NewRecorder()
	GetUserEffectiveRoles(d)(rec3, req3)
	var resp3 map[string][]string
	if err := json.Unmarshal(rec3.Body.Bytes(), &resp3); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp3["roles"]) != 0 {
		t.Fatalf("expected no roles after revoke, got %+v", resp3["roles"])
	}
}

func TestRevokeUserRole_InvalidJSON_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("revokebad-%d", time.Now().UnixNano()))

	rec := doRBACRequest(t, RevokeUserRole(d), http.MethodDelete, "/admin/rbac/users/"+u.ID+"/roles", `{not json`, map[string]string{"userId": u.ID})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestAssignGroupRole_MembersInheritRole is the group-role-assignment
// counterpart: assigning a role to a group must make it show up in every
// member's effective roles (GetEffectiveRoles' UNION over direct +
// group-derived assignments).
func TestAssignGroupRole_MembersInheritRole(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	clientID := fmt.Sprintf("client-%d", time.Now().UnixNano())
	groupID := createTestGroup(t, d, fmt.Sprintf("g-%d", time.Now().UnixNano()))
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("groupinherit-%d", time.Now().UnixNano()))
	createTestClientRole(t, d, clientID, "moderator")

	if err := d.RBAC.AddGroupMember(context.Background(), groupID, u.ID); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}

	rec := doRBACRequest(t, AssignGroupRole(d), http.MethodPost, "/admin/rbac/groups/"+groupID+"/roles",
		fmt.Sprintf(`{"client_id":%q,"role_name":"moderator"}`, clientID), map[string]string{"id": groupID})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	roles, err := d.RBAC.GetEffectiveRoles(context.Background(), u.ID, clientID)
	if err != nil {
		t.Fatalf("GetEffectiveRoles: %v", err)
	}
	found := false
	for _, r := range roles {
		if r == "moderator" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected user to inherit 'moderator' via group, got %+v", roles)
	}
}

func TestAssignGroupRole_MissingFields_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	groupID := createTestGroup(t, d, fmt.Sprintf("g-%d", time.Now().UnixNano()))

	rec := doRBACRequest(t, AssignGroupRole(d), http.MethodPost, "/admin/rbac/groups/"+groupID+"/roles", `{}`, map[string]string{"id": groupID})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// --- Policy handlers ---

func TestCreatePolicy_MissingFields_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)

	rec := doRBACRequest(t, CreatePolicy(d), http.MethodPost, "/admin/rbac/policies", `{"description":"missing name and type"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreatePolicy_ListPolicy_DeletePolicy exercises the policy lifecycle
// and confirms newly created policies (enabled by DB default) show up in
// ListPolicies, which only returns enabled=true rows.
func TestCreatePolicy_ListPolicy_DeletePolicy(t *testing.T) {
	pool := requireDB(t)
	d := testRBACDeps(t, pool)
	name := fmt.Sprintf("policy-%d", time.Now().UnixNano())

	body := fmt.Sprintf(`{"name":%q,"type":"require_mfa","description":"test policy"}`, name)
	rec := doRBACRequest(t, CreatePolicy(d), http.MethodPost, "/admin/rbac/policies", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d (body: %s)", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var created map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	id := created["id"]
	if id == "" {
		t.Fatalf("expected non-empty id in %v", created)
	}
	cleanupPolicy(t, d, id)

	listRec := doRBACRequest(t, ListPolicies(d), http.MethodGet, "/admin/rbac/policies", "", nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRec.Code, http.StatusOK)
	}
	var policies []rbac.Policy
	if err := json.Unmarshal(listRec.Body.Bytes(), &policies); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, p := range policies {
		if p.ID == id {
			found = true
			if !p.Enabled {
				t.Errorf("expected policy to be enabled by default, got %+v", p)
			}
		}
	}
	if !found {
		t.Fatalf("created policy %s not found in list %+v", id, policies)
	}

	delRec := doRBACRequest(t, DeletePolicy(d), http.MethodDelete, "/admin/rbac/policies/"+id, "", map[string]string{"id": id})
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d", delRec.Code, http.StatusNoContent)
	}

	listRec2 := doRBACRequest(t, ListPolicies(d), http.MethodGet, "/admin/rbac/policies", "", nil)
	var policies2 []rbac.Policy
	if err := json.Unmarshal(listRec2.Body.Bytes(), &policies2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, p := range policies2 {
		if p.ID == id {
			t.Fatalf("policy %s still present after delete", id)
		}
	}
}
