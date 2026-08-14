//go:build integration

package rbac

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestListGroups_CreateDelete exercises the ListGroups/DeleteGroup pair,
// which the original store_test.go left uncovered.
func TestListGroups_CreateDelete(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	name := fmt.Sprintf("list-group-%d", time.Now().UnixNano())
	id, err := s.CreateGroup(ctx, name, "a test group")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	groups, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	var found bool
	for _, g := range groups {
		if g.ID == id {
			found = true
			if g.Name != name {
				t.Errorf("group name = %q, want %q", g.Name, name)
			}
			if g.Description != "a test group" {
				t.Errorf("group description = %q, want %q", g.Description, "a test group")
			}
		}
	}
	if !found {
		t.Fatalf("ListGroups did not include newly created group %s", id)
	}

	if err := s.DeleteGroup(ctx, id); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}

	groups, err = s.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups after delete: %v", err)
	}
	for _, g := range groups {
		if g.ID == id {
			t.Fatalf("DeleteGroup did not remove group %s from ListGroups", id)
		}
	}
}

// TestListGroupMembers_Empty proves an empty (never-populated) group
// returns an empty slice/nil, not an error.
func TestListGroupMembers_Empty(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	groupID, err := s.CreateGroup(ctx, fmt.Sprintf("empty-group-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, groupID) })

	members, err := s.ListGroupMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("ListGroupMembers on empty group = %v, want empty", members)
	}
}

// TestClientRoles_CreateListDelete covers ListClientRoles/CreateClientRole/
// DeleteClientRole, entirely uncovered previously.
func TestClientRoles_CreateListDelete(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	clientID := fmt.Sprintf("cr-client-%d", time.Now().UnixNano())
	roleName := "operator"
	id, err := s.CreateClientRole(ctx, clientID, roleName, "can operate things")
	if err != nil {
		t.Fatalf("CreateClientRole: %v", err)
	}

	roles, err := s.ListClientRoles(ctx, clientID)
	if err != nil {
		t.Fatalf("ListClientRoles: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("ListClientRoles = %d roles, want 1", len(roles))
	}
	if roles[0].ID != id || roles[0].Name != roleName || roles[0].ClientID != clientID {
		t.Errorf("ListClientRoles[0] = %+v, want id=%s name=%s client=%s", roles[0], id, roleName, clientID)
	}

	// A different client must not see this role.
	otherRoles, err := s.ListClientRoles(ctx, "some-other-client")
	if err != nil {
		t.Fatalf("ListClientRoles (other client): %v", err)
	}
	if len(otherRoles) != 0 {
		t.Fatalf("ListClientRoles leaked role across clients: %+v", otherRoles)
	}

	if err := s.DeleteClientRole(ctx, id); err != nil {
		t.Fatalf("DeleteClientRole: %v", err)
	}
	roles, err = s.ListClientRoles(ctx, clientID)
	if err != nil {
		t.Fatalf("ListClientRoles after delete: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("ListClientRoles after DeleteClientRole = %+v, want empty", roles)
	}
}

// TestGetEffectiveRoles_DirectAndGroup is the most security-relevant
// uncovered path: it proves a user's effective roles for a client combine
// (a) directly assigned roles and (b) roles inherited via group
// membership, deduplicated, and that roles scoped to a different client
// never leak in.
func TestGetEffectiveRoles_DirectAndGroup(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("effuser%d", time.Now().UnixNano()))
	clientID := fmt.Sprintf("eff-client-%d", time.Now().UnixNano())
	otherClientID := fmt.Sprintf("eff-other-client-%d", time.Now().UnixNano())

	// Direct role assignment.
	if err := s.AssignUserRole(ctx, userID, clientID, "direct-role"); err != nil {
		t.Fatalf("AssignUserRole: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM user_client_roles WHERE user_id=$1`, userID) })

	// A role on a different client must not leak into this client's
	// effective roles — this is the core tenant/client isolation guarantee.
	if err := s.AssignUserRole(ctx, userID, otherClientID, "other-client-role"); err != nil {
		t.Fatalf("AssignUserRole (other client): %v", err)
	}

	// Group-inherited role.
	groupID, err := s.CreateGroup(ctx, fmt.Sprintf("eff-group-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, groupID) })

	if err := s.AddGroupMember(ctx, groupID, userID); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	if err := s.AssignGroupRole(ctx, groupID, clientID, "group-role"); err != nil {
		t.Fatalf("AssignGroupRole: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM group_client_roles WHERE group_id=$1`, groupID)
	})

	roles, err := s.GetEffectiveRoles(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetEffectiveRoles: %v", err)
	}

	roleSet := map[string]bool{}
	for _, r := range roles {
		roleSet[r] = true
	}
	if !roleSet["direct-role"] {
		t.Errorf("GetEffectiveRoles = %v, missing direct-role", roles)
	}
	if !roleSet["group-role"] {
		t.Errorf("GetEffectiveRoles = %v, missing group-role (via group membership)", roles)
	}
	if roleSet["other-client-role"] {
		t.Errorf("GetEffectiveRoles = %v, leaked other-client-role from a different client", roles)
	}
	if len(roles) != 2 {
		t.Errorf("GetEffectiveRoles = %v (%d roles), want exactly 2 (direct-role, group-role)", roles, len(roles))
	}
}

// TestGetEffectiveRoles_RemovingGroupMembershipRevokesInheritedRole proves
// that removing a user from a group actually revokes the role they
// inherited from it — a stale/cached membership here would be a privilege
// escalation (or at minimum an incorrect authorization) bug.
func TestGetEffectiveRoles_RemovingGroupMembershipRevokesInheritedRole(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("revokeuser%d", time.Now().UnixNano()))
	clientID := fmt.Sprintf("revoke-client-%d", time.Now().UnixNano())

	groupID, err := s.CreateGroup(ctx, fmt.Sprintf("revoke-group-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, groupID) })

	if err := s.AddGroupMember(ctx, groupID, userID); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	if err := s.AssignGroupRole(ctx, groupID, clientID, "admin"); err != nil {
		t.Fatalf("AssignGroupRole: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM group_client_roles WHERE group_id=$1`, groupID)
	})

	roles, err := s.GetEffectiveRoles(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetEffectiveRoles: %v", err)
	}
	if !hasRole(roles, "admin") {
		t.Fatalf("expected user to hold admin via group membership, got %v", roles)
	}

	if err := s.RemoveGroupMember(ctx, groupID, userID); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}

	roles, err = s.GetEffectiveRoles(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetEffectiveRoles after removal: %v", err)
	}
	if hasRole(roles, "admin") {
		t.Fatalf("user still holds admin after RemoveGroupMember — stale inherited role, roles=%v", roles)
	}
}

// TestAssignRevokeGroupRole exercises AssignGroupRole/RevokeGroupRole
// directly (not just through GetEffectiveRoles), including the ON CONFLICT
// DO NOTHING idempotency of a duplicate assign.
func TestAssignRevokeGroupRole(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	groupID, err := s.CreateGroup(ctx, fmt.Sprintf("gr-group-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, groupID) })

	clientID := fmt.Sprintf("gr-client-%d", time.Now().UnixNano())

	if err := s.AssignGroupRole(ctx, groupID, clientID, "viewer"); err != nil {
		t.Fatalf("AssignGroupRole: %v", err)
	}
	// Duplicate assignment must be idempotent (ON CONFLICT DO NOTHING), not error.
	if err := s.AssignGroupRole(ctx, groupID, clientID, "viewer"); err != nil {
		t.Fatalf("AssignGroupRole (duplicate): %v", err)
	}

	if err := s.RevokeGroupRole(ctx, groupID, clientID, "viewer"); err != nil {
		t.Fatalf("RevokeGroupRole: %v", err)
	}

	var count int
	err = pool.QueryRow(ctx,
		`SELECT count(*) FROM group_client_roles WHERE group_id=$1 AND client_id=$2 AND role_name=$3`,
		groupID, clientID, "viewer",
	).Scan(&count)
	if err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 0 {
		t.Fatalf("RevokeGroupRole left %d row(s) behind, want 0", count)
	}
}
