//go:build integration

package rbac

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
// integration-test gating pattern used in internal/organization/store_test.go.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SINAUTH_TEST_DB_URL")
	if url == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping rbac store integration test")
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
// verify (a) the store methods call it with the expected relationship shape,
// and (b) a Checker error is best-effort (logged, not propagated/fatal).
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

func TestAddRemoveGroupMember_SyncsToChecker(t *testing.T) {
	pool := requireDB(t)
	checker := &fakeChecker{}
	s := NewStore(pool, checker)
	ctx := context.Background()

	groupID, err := s.CreateGroup(ctx, fmt.Sprintf("test-group-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, groupID) })

	userID := createTestUser(t, pool, fmt.Sprintf("rbacuser%d", time.Now().UnixNano()))

	if err := s.AddGroupMember(ctx, groupID, userID); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	writes := checker.Writes()
	if len(writes) != 1 {
		t.Fatalf("expected 1 WriteRelationship call, got %d", len(writes))
	}
	want := authz.Relationship{
		Entity:   authz.Entity{Type: "group", ID: groupID},
		Relation: "member",
		Subject:  authz.Entity{Type: "user", ID: userID},
	}
	if writes[0] != want {
		t.Errorf("WriteRelationship called with %+v, want %+v", writes[0], want)
	}

	if err := s.RemoveGroupMember(ctx, groupID, userID); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	deletes := checker.Deletes()
	if len(deletes) != 1 {
		t.Fatalf("expected 1 DeleteRelationship call, got %d", len(deletes))
	}
	if deletes[0] != want {
		t.Errorf("DeleteRelationship called with %+v, want %+v", deletes[0], want)
	}
}

func TestAssignRevokeUserRole_SyncsToChecker(t *testing.T) {
	pool := requireDB(t)
	checker := &fakeChecker{}
	s := NewStore(pool, checker)
	ctx := context.Background()

	clientID := fmt.Sprintf("test-client-%d", time.Now().UnixNano())
	roleName := "analyst"
	userID := createTestUser(t, pool, fmt.Sprintf("roleuser%d", time.Now().UnixNano()))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM user_client_roles WHERE user_id=$1`, userID)
	})

	if err := s.AssignUserRole(ctx, userID, clientID, roleName); err != nil {
		t.Fatalf("AssignUserRole: %v", err)
	}
	writes := checker.Writes()
	if len(writes) != 1 {
		t.Fatalf("expected 1 WriteRelationship call, got %d", len(writes))
	}
	want := authz.Relationship{
		Entity:   authz.Entity{Type: "client_role", ID: clientID + ":" + roleName},
		Relation: "assignee",
		Subject:  authz.Entity{Type: "user", ID: userID},
	}
	if writes[0] != want {
		t.Errorf("WriteRelationship called with %+v, want %+v", writes[0], want)
	}

	if err := s.RevokeUserRole(ctx, userID, clientID, roleName); err != nil {
		t.Fatalf("RevokeUserRole: %v", err)
	}
	deletes := checker.Deletes()
	if len(deletes) != 1 {
		t.Fatalf("expected 1 DeleteRelationship call, got %d", len(deletes))
	}
	if deletes[0] != want {
		t.Errorf("DeleteRelationship called with %+v, want %+v", deletes[0], want)
	}
}

// TestCheckerErrorDoesNotFailStoreMethod is the best-effort-semantics test:
// a Permify sync failure must never cause AddGroupMember/RemoveGroupMember
// (or the equivalent role methods) to return an error, since Postgres is
// authoritative and the SQL write already succeeded.
func TestCheckerErrorDoesNotFailStoreMethod(t *testing.T) {
	pool := requireDB(t)
	checker := &fakeChecker{
		writeErr:  errors.New("permify unreachable"),
		deleteErr: errors.New("permify unreachable"),
	}
	s := NewStore(pool, checker)
	ctx := context.Background()

	groupID, err := s.CreateGroup(ctx, fmt.Sprintf("test-group-err-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, groupID) })

	userID := createTestUser(t, pool, fmt.Sprintf("erruser%d", time.Now().UnixNano()))

	if err := s.AddGroupMember(ctx, groupID, userID); err != nil {
		t.Fatalf("AddGroupMember should succeed despite Checker error, got: %v", err)
	}
	members, err := s.ListGroupMembers(ctx, groupID)
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected the SQL write to have gone through despite Checker error, got members=%+v", members)
	}

	if err := s.RemoveGroupMember(ctx, groupID, userID); err != nil {
		t.Fatalf("RemoveGroupMember should succeed despite Checker error, got: %v", err)
	}
}

func TestNewStore_DefaultsToNoopChecker(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool) // no checker passed
	ctx := context.Background()

	groupID, err := s.CreateGroup(ctx, fmt.Sprintf("test-group-noop-%d", time.Now().UnixNano()), "")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, groupID) })

	userID := createTestUser(t, pool, fmt.Sprintf("noopuser%d", time.Now().UnixNano()))

	// Should not panic on a nil checker and should still perform the SQL write.
	if err := s.AddGroupMember(ctx, groupID, userID); err != nil {
		t.Fatalf("AddGroupMember with default (Noop) checker: %v", err)
	}
}
