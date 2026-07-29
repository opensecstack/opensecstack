//go:build integration

package organization

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/sinauth/internal/authz"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used elsewhere in the ecosystem (e.g.
// vertguard/internal/ioc/store_test.go).
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SINAUTH_TEST_DB_URL")
	if url == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping organization store integration test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// createTestUser inserts a minimal user row and returns its id.
func createTestUser(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id`,
		username, username+"@example.com",
	).Scan(&id)
	if err != nil {
		t.Fatalf("createTestUser: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, id) })
	return id
}

// fakeChecker records every WriteRelationship/DeleteRelationship call it
// receives, and can be configured to return an error from either — used to
// verify (a) AddMember/RemoveMember call it with the expected relationship
// shape, and (b) a Checker error is best-effort (logged, not
// propagated/fatal) rather than failing the store method.
type fakeChecker struct {
	mu        sync.Mutex
	writes    []authz.Relationship
	deletes   []authz.Relationship
	writeErr  error
	deleteErr error
}

func (f *fakeChecker) Check(context.Context, authz.Entity, string, authz.Entity) (bool, error) {
	return true, nil
}

func (f *fakeChecker) WriteRelationship(_ context.Context, rel authz.Relationship) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, rel)
	return f.writeErr
}

func (f *fakeChecker) DeleteRelationship(_ context.Context, rel authz.Relationship) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, rel)
	return f.deleteErr
}

func (f *fakeChecker) Writes() []authz.Relationship {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]authz.Relationship, len(f.writes))
	copy(out, f.writes)
	return out
}

func (f *fakeChecker) Deletes() []authz.Relationship {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]authz.Relationship, len(f.deletes))
	copy(out, f.deletes)
	return out
}

var _ authz.Checker = (*fakeChecker)(nil)

func TestAddRemoveMember_SyncsToChecker(t *testing.T) {
	pool := requireDB(t)
	checker := &fakeChecker{}
	s := NewStore(pool, checker)
	ctx := context.Background()

	slug := fmt.Sprintf("test-org-sync-%d", time.Now().UnixNano())
	org, err := s.Create(ctx, Organization{LegalName: "Sync Org", Slug: slug, OrgType: "private"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID) })

	userID := createTestUser(t, pool, fmt.Sprintf("syncuser%d", time.Now().UnixNano()))

	if err := s.AddMember(ctx, org.ID, userID, "owner"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	writes := checker.Writes()
	if len(writes) != 1 {
		t.Fatalf("expected 1 WriteRelationship call, got %d", len(writes))
	}
	want := authz.Relationship{
		Entity:   authz.Entity{Type: "organization", ID: org.ID},
		Relation: "owner",
		Subject:  authz.Entity{Type: "user", ID: userID},
	}
	if writes[0] != want {
		t.Errorf("WriteRelationship called with %+v, want %+v", writes[0], want)
	}

	if err := s.RemoveMember(ctx, org.ID, userID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	deletes := checker.Deletes()
	if len(deletes) != 1 {
		t.Fatalf("expected 1 DeleteRelationship call, got %d", len(deletes))
	}
	if deletes[0] != want {
		t.Errorf("DeleteRelationship called with %+v, want %+v", deletes[0], want)
	}
}

// TestCheckerErrorDoesNotFailAddRemoveMember is the best-effort-semantics
// test: a Permify sync failure must never cause AddMember/RemoveMember to
// return an error, since Postgres organization_members is authoritative and
// the SQL write already succeeded.
func TestCheckerErrorDoesNotFailAddRemoveMember(t *testing.T) {
	pool := requireDB(t)
	checker := &fakeChecker{
		writeErr:  errors.New("permify unreachable"),
		deleteErr: errors.New("permify unreachable"),
	}
	s := NewStore(pool, checker)
	ctx := context.Background()

	slug := fmt.Sprintf("test-org-err-%d", time.Now().UnixNano())
	org, err := s.Create(ctx, Organization{LegalName: "Err Org", Slug: slug, OrgType: "private"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID) })

	userID := createTestUser(t, pool, fmt.Sprintf("errmemberuser%d", time.Now().UnixNano()))

	if err := s.AddMember(ctx, org.ID, userID, "member"); err != nil {
		t.Fatalf("AddMember should succeed despite Checker error, got: %v", err)
	}
	members, err := s.ListMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected the SQL write to have gone through despite Checker error, got members=%+v", members)
	}

	if err := s.RemoveMember(ctx, org.ID, userID); err != nil {
		t.Fatalf("RemoveMember should succeed despite Checker error, got: %v", err)
	}
}

func TestNewStore_DefaultsToNoopChecker(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool) // no checker passed
	ctx := context.Background()

	slug := fmt.Sprintf("test-org-noop-%d", time.Now().UnixNano())
	org, err := s.Create(ctx, Organization{LegalName: "Noop Org", Slug: slug, OrgType: "private"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID) })

	userID := createTestUser(t, pool, fmt.Sprintf("noopmemberuser%d", time.Now().UnixNano()))

	// Should not panic with a default (Noop) checker and should still
	// perform the SQL write.
	if err := s.AddMember(ctx, org.ID, userID, "member"); err != nil {
		t.Fatalf("AddMember with default (Noop) checker: %v", err)
	}
}

func TestStoreCreateGetListDelete(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	slug := fmt.Sprintf("test-org-%d", time.Now().UnixNano())
	created, err := s.Create(ctx, Organization{
		LegalName: "Test Org",
		Slug:      slug,
		OrgType:   "private",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, created.ID) })

	if created.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if created.Status != "pending" {
		t.Errorf("Status = %q, want pending", created.Status)
	}

	got, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LegalName != "Test Org" || got.Slug != slug {
		t.Errorf("Get returned %+v", got)
	}

	orgs, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, o := range orgs {
		if o.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Error("List did not include created organization")
	}

	if err := s.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, created.ID); err == nil {
		t.Error("expected error getting deleted organization")
	}
}

func TestStoreMembership(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	slug := fmt.Sprintf("test-org-mem-%d", time.Now().UnixNano())
	org, err := s.Create(ctx, Organization{LegalName: "Member Org", Slug: slug, OrgType: "government"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org.ID) })

	userID := createTestUser(t, pool, fmt.Sprintf("orguser%d", time.Now().UnixNano()))

	if err := s.AddMember(ctx, org.ID, userID, "admin"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	members, err := s.ListMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 || members[0].OrgRole != "admin" || members[0].OrgType != "government" {
		t.Fatalf("ListMembers = %+v", members)
	}

	memberships, err := s.MembershipsForUser(ctx, userID)
	if err != nil {
		t.Fatalf("MembershipsForUser: %v", err)
	}
	if len(memberships) != 1 || memberships[0].OrganizationID != org.ID || memberships[0].Slug != slug {
		t.Fatalf("MembershipsForUser = %+v", memberships)
	}

	if err := s.RemoveMember(ctx, org.ID, userID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	memberships, err = s.MembershipsForUser(ctx, userID)
	if err != nil {
		t.Fatalf("MembershipsForUser after remove: %v", err)
	}
	if len(memberships) != 0 {
		t.Fatalf("expected no memberships after remove, got %+v", memberships)
	}
}
