//go:build integration

package organization

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func uniqueSlug(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func TestStore_Get_NotFound(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	if _, err := s.Get(context.Background(), "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("expected an error getting a non-existent organization")
	}
}

func TestStore_Create_DuplicateSlug(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	slug := uniqueSlug("dup-org")
	org, err := s.Create(ctx, Organization{LegalName: "First Org", Slug: slug, OrgType: "private"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID) })

	_, err = s.Create(ctx, Organization{LegalName: "Second Org", Slug: slug, OrgType: "private"})
	if err == nil {
		t.Fatal("expected an error creating an organization with a duplicate slug")
	}
	var pgErr *pgconn.PgError
	if !isPgError(err, &pgErr) || pgErr.Code != "23505" {
		t.Errorf("expected a unique_violation (23505) from the slug uniqueness constraint, got: %v", err)
	}
}

func TestStore_Create_InvalidOrgType(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	_, err := s.Create(ctx, Organization{LegalName: "Bad Type Org", Slug: uniqueSlug("badtype"), OrgType: "not-a-real-type"})
	if err == nil {
		t.Fatal("expected an error creating an organization with an org_type outside the CHECK constraint")
	}
}

func TestStore_AddMember_DefaultsToMemberRole(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	org, err := s.Create(ctx, Organization{LegalName: "Default Role Org", Slug: uniqueSlug("defrole"), OrgType: "private"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID) })

	userID := createTestUser(t, pool, uniqueSlug("defroleuser"))

	if err := s.AddMember(ctx, org.ID, userID, ""); err != nil {
		t.Fatalf("AddMember with empty role: %v", err)
	}

	members, err := s.ListMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 || members[0].OrgRole != "member" {
		t.Fatalf("ListMembers = %+v, want a single member with org_role=member", members)
	}
}

func TestStore_AddMember_RejectsInvalidRole(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	org, err := s.Create(ctx, Organization{LegalName: "Bad Role Org", Slug: uniqueSlug("badrole"), OrgType: "private"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID) })

	userID := createTestUser(t, pool, uniqueSlug("badroleuser"))

	if err := s.AddMember(ctx, org.ID, userID, "superadmin"); err == nil {
		t.Fatal("expected an error adding a member with an org_role outside the CHECK constraint (owner/admin/member)")
	}
}

func TestStore_AddMember_UpsertsRoleOnConflict(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	org, err := s.Create(ctx, Organization{LegalName: "Upsert Org", Slug: uniqueSlug("upsert"), OrgType: "private"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID) })

	userID := createTestUser(t, pool, uniqueSlug("upsertuser"))

	if err := s.AddMember(ctx, org.ID, userID, "member"); err != nil {
		t.Fatalf("AddMember (member): %v", err)
	}
	if err := s.AddMember(ctx, org.ID, userID, "admin"); err != nil {
		t.Fatalf("AddMember (upsert to admin): %v", err)
	}

	members, err := s.ListMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected the upsert to leave exactly one membership row, got %d", len(members))
	}
	if members[0].OrgRole != "admin" {
		t.Errorf("OrgRole after upsert = %q, want %q", members[0].OrgRole, "admin")
	}
}

func TestStore_RemoveMember_NonMemberIsNotAnError(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	org, err := s.Create(ctx, Organization{LegalName: "Remove Nonmember Org", Slug: uniqueSlug("rmnonmem"), OrgType: "private"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID) })

	userID := createTestUser(t, pool, uniqueSlug("neverjoined"))

	// The user was never added as a member; RemoveMember must be a no-op,
	// not an error, per its best-effort-sync documentation.
	if err := s.RemoveMember(ctx, org.ID, userID); err != nil {
		t.Fatalf("RemoveMember for a non-member: %v", err)
	}
}

// TestStore_MultiTenancyIsolation_ListMembers is the IDOR-class regression
// test called out in this task: a query scoped to organization A must never
// return rows belonging to organization B, even when both organizations
// share a member.
func TestStore_MultiTenancyIsolation_ListMembers(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	orgA, err := s.Create(ctx, Organization{LegalName: "Tenant A", Slug: uniqueSlug("tenant-a"), OrgType: "private"})
	if err != nil {
		t.Fatalf("Create orgA: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, orgA.ID) })

	orgB, err := s.Create(ctx, Organization{LegalName: "Tenant B", Slug: uniqueSlug("tenant-b"), OrgType: "government"})
	if err != nil {
		t.Fatalf("Create orgB: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, orgB.ID) })

	userOnlyA := createTestUser(t, pool, uniqueSlug("useronlya"))
	userOnlyB := createTestUser(t, pool, uniqueSlug("useronlyb"))
	sharedUser := createTestUser(t, pool, uniqueSlug("shareduser"))

	if err := s.AddMember(ctx, orgA.ID, userOnlyA, "owner"); err != nil {
		t.Fatalf("AddMember userOnlyA->orgA: %v", err)
	}
	if err := s.AddMember(ctx, orgB.ID, userOnlyB, "owner"); err != nil {
		t.Fatalf("AddMember userOnlyB->orgB: %v", err)
	}
	if err := s.AddMember(ctx, orgA.ID, sharedUser, "member"); err != nil {
		t.Fatalf("AddMember sharedUser->orgA: %v", err)
	}
	if err := s.AddMember(ctx, orgB.ID, sharedUser, "admin"); err != nil {
		t.Fatalf("AddMember sharedUser->orgB: %v", err)
	}

	// orgA has exactly 2 members (userOnlyA, sharedUser); orgB has exactly 2
	// (userOnlyB, sharedUser). If ListMembers leaked across tenants, one of
	// these counts would come back as 3 (both organizations' members
	// combined) instead of 2 — that is the IDOR signature this test guards
	// against.
	membersA, err := s.ListMembers(ctx, orgA.ID)
	if err != nil {
		t.Fatalf("ListMembers(orgA): %v", err)
	}
	if len(membersA) != 2 {
		t.Fatalf("SECURITY: ListMembers(orgA) returned %d members, want 2 — possible cross-tenant leak: %+v", len(membersA), membersA)
	}
	for _, m := range membersA {
		if m.OrganizationID != orgA.ID {
			t.Fatalf("SECURITY: ListMembers(orgA) returned a row scoped to organization %q — cross-tenant leak", m.OrganizationID)
		}
	}
	rolesA := map[string]bool{}
	for _, m := range membersA {
		rolesA[m.OrgRole] = true
	}
	if !rolesA["owner"] || !rolesA["member"] {
		t.Errorf("ListMembers(orgA) roles = %+v, want to include owner and member", membersA)
	}

	membersB, err := s.ListMembers(ctx, orgB.ID)
	if err != nil {
		t.Fatalf("ListMembers(orgB): %v", err)
	}
	if len(membersB) != 2 {
		t.Fatalf("SECURITY: ListMembers(orgB) returned %d members, want 2 — possible cross-tenant leak: %+v", len(membersB), membersB)
	}
	for _, m := range membersB {
		if m.OrganizationID != orgB.ID {
			t.Fatalf("SECURITY: ListMembers(orgB) returned a row scoped to organization %q — cross-tenant leak", m.OrganizationID)
		}
	}
	rolesB := map[string]bool{}
	for _, m := range membersB {
		rolesB[m.OrgRole] = true
	}
	if !rolesB["owner"] || !rolesB["admin"] {
		t.Errorf("ListMembers(orgB) roles = %+v, want to include owner and admin", membersB)
	}
}

// TestStore_MultiTenancyIsolation_MembershipsForUser confirms the inverse
// direction: a user's membership listing must include exactly the
// organizations they belong to and nothing else, in particular never a
// sibling organization's data merely because it happens to exist.
func TestStore_MultiTenancyIsolation_MembershipsForUser(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	orgA, err := s.Create(ctx, Organization{LegalName: "Membership Tenant A", Slug: uniqueSlug("mem-tenant-a"), OrgType: "private"})
	if err != nil {
		t.Fatalf("Create orgA: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, orgA.ID) })

	orgB, err := s.Create(ctx, Organization{LegalName: "Membership Tenant B", Slug: uniqueSlug("mem-tenant-b"), OrgType: "ngo"})
	if err != nil {
		t.Fatalf("Create orgB: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, orgB.ID) })

	userA := createTestUser(t, pool, uniqueSlug("membonlya"))
	userB := createTestUser(t, pool, uniqueSlug("membonlyb"))

	if err := s.AddMember(ctx, orgA.ID, userA, "owner"); err != nil {
		t.Fatalf("AddMember userA->orgA: %v", err)
	}
	if err := s.AddMember(ctx, orgB.ID, userB, "owner"); err != nil {
		t.Fatalf("AddMember userB->orgB: %v", err)
	}

	membershipsA, err := s.MembershipsForUser(ctx, userA)
	if err != nil {
		t.Fatalf("MembershipsForUser(userA): %v", err)
	}
	if len(membershipsA) != 1 || membershipsA[0].OrganizationID != orgA.ID {
		t.Fatalf("SECURITY: MembershipsForUser(userA) = %+v, want exactly [orgA] — cross-tenant leak if orgB appears", membershipsA)
	}

	membershipsB, err := s.MembershipsForUser(ctx, userB)
	if err != nil {
		t.Fatalf("MembershipsForUser(userB): %v", err)
	}
	if len(membershipsB) != 1 || membershipsB[0].OrganizationID != orgB.ID {
		t.Fatalf("SECURITY: MembershipsForUser(userB) = %+v, want exactly [orgB] — cross-tenant leak if orgA appears", membershipsB)
	}
}

func isPgError(err error, target **pgconn.PgError) bool {
	for e := err; e != nil; {
		if pe, ok := e.(*pgconn.PgError); ok {
			*target = pe
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
