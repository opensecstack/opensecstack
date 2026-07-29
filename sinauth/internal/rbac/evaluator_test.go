//go:build integration

package rbac

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/opensecstack/sinauth/internal/authz"
)

// requireDB is defined in store_test.go (same package, same build tag) —
// reused here rather than redeclared.

// evalFakeChecker is an in-memory authz.Checker used so these tests never need a
// real Permify deployment: allow is keyed by "subjectType:subjectID
// permission entityType:entityID".
type evalFakeChecker struct {
	allow map[string]bool
}

func newEvalFakeChecker() *evalFakeChecker { return &evalFakeChecker{allow: map[string]bool{}} }

func (f *evalFakeChecker) key(subject authz.Entity, permission string, entity authz.Entity) string {
	return fmt.Sprintf("%s:%s %s %s:%s", subject.Type, subject.ID, permission, entity.Type, entity.ID)
}

func (f *evalFakeChecker) allowFor(subject authz.Entity, permission string, entity authz.Entity) {
	f.allow[f.key(subject, permission, entity)] = true
}

func (f *evalFakeChecker) Check(_ context.Context, subject authz.Entity, permission string, entity authz.Entity) (bool, error) {
	return f.allow[f.key(subject, permission, entity)], nil
}

func (f *evalFakeChecker) WriteRelationship(_ context.Context, _ authz.Relationship) error  { return nil }
func (f *evalFakeChecker) DeleteRelationship(_ context.Context, _ authz.Relationship) error { return nil }

var _ authz.Checker = (*evalFakeChecker)(nil)

func createPolicy(t *testing.T, s *Store, p Policy) string {
	t.Helper()
	p.Enabled = true
	id, err := s.CreatePolicy(context.Background(), p)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	t.Cleanup(func() { _ = s.DeletePolicy(context.Background(), id) })
	return id
}

// TestEvaluate_NoPolicies_Unchanged proves the common case today (no
// policies configured) is unaffected by wiring Evaluate into real token
// issuance: it must still return nil, exactly as before this workstream.
func TestEvaluate_NoPolicies_Unchanged(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	tc := TokenContext{
		UserID:   "11111111-1111-1111-1111-111111111111",
		ClientID: fmt.Sprintf("unused-client-%d", time.Now().UnixNano()),
		Roles:    []string{"viewer"},
	}
	if err := s.Evaluate(ctx, tc); err != nil {
		t.Fatalf("Evaluate with no policies = %v, want nil", err)
	}
}

// TestEvaluate_DenyRole_DirectRoleMatch_Blocks is the pre-existing
// direct-role-string deny_role behavior — must keep working unchanged.
func TestEvaluate_DenyRole_DirectRoleMatch_Blocks(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	clientID := fmt.Sprintf("deny-client-%d", time.Now().UnixNano())
	createPolicy(t, s, Policy{Name: fmt.Sprintf("deny-banned-%d", time.Now().UnixNano()), Type: "deny_role", ClientID: clientID, RoleName: "banned"})

	tc := TokenContext{
		UserID:   "22222222-2222-2222-2222-222222222222",
		ClientID: clientID,
		Roles:    []string{"banned"},
	}
	if err := s.Evaluate(ctx, tc); err == nil {
		t.Fatal("Evaluate = nil, want deny_role error for matching direct role")
	}
}

// TestEvaluate_DenyRole_ViaAuthzChecker_Blocks proves the additive Permify
// path: a deny_role policy now also blocks when the role is held purely via
// the authz.Checker's client_role "use" permission, even though it is
// absent from tc.Roles (the direct-role-string check alone would miss it).
func TestEvaluate_DenyRole_ViaAuthzChecker_Blocks(t *testing.T) {
	pool := requireDB(t)
	checker := newEvalFakeChecker()
	s := NewStore(pool, checker)
	ctx := context.Background()

	clientID := fmt.Sprintf("deny-client-authz-%d", time.Now().UnixNano())
	userID := "33333333-3333-3333-3333-333333333333"
	roleName := "banned-via-permify"
	createPolicy(t, s, Policy{Name: fmt.Sprintf("deny-authz-%d", time.Now().UnixNano()), Type: "deny_role", ClientID: clientID, RoleName: roleName})

	checker.allowFor(
		authz.Entity{Type: "user", ID: userID},
		"use",
		authz.Entity{Type: "client_role", ID: clientRoleID(clientID, roleName)},
	)

	tc := TokenContext{
		UserID:   userID,
		ClientID: clientID,
		Roles:    nil, // deliberately empty — the direct-role check alone would not catch this
	}
	if err := s.Evaluate(ctx, tc); err == nil {
		t.Fatal("Evaluate = nil, want deny_role error via authz.Checker match")
	}
}

// TestEvaluate_DenyRole_AuthzCheckerDenies_DoesNotBlockOtherRoles proves the
// authz-backed check is scoped to the specific role/client pair — a checker
// that denies must not cause unrelated evaluations to fail.
func TestEvaluate_DenyRole_AuthzCheckerDenies_DoesNotBlockOtherRoles(t *testing.T) {
	pool := requireDB(t)
	checker := newEvalFakeChecker() // allows nothing
	s := NewStore(pool, checker)
	ctx := context.Background()

	clientID := fmt.Sprintf("deny-client-noauthz-%d", time.Now().UnixNano())
	createPolicy(t, s, Policy{Name: fmt.Sprintf("deny-noauthz-%d", time.Now().UnixNano()), Type: "deny_role", ClientID: clientID, RoleName: "banned"})

	tc := TokenContext{
		UserID:   "44444444-4444-4444-4444-444444444444",
		ClientID: clientID,
		Roles:    []string{"allowed-role"},
	}
	if err := s.Evaluate(ctx, tc); err != nil {
		t.Fatalf("Evaluate = %v, want nil (role not denied by either check)", err)
	}
}

// TestEvaluate_RequireEmailVerified_Unchanged is a light regression check
// that the pre-existing require_email_verified behavior is untouched by the
// deny_role/authz additions.
func TestEvaluate_RequireEmailVerified_Unchanged(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	clientID := fmt.Sprintf("email-client-%d", time.Now().UnixNano())
	createPolicy(t, s, Policy{Name: fmt.Sprintf("require-email-%d", time.Now().UnixNano()), Type: "require_email_verified", ClientID: clientID})

	tc := TokenContext{UserID: "u1", ClientID: clientID, EmailVerified: false}
	if err := s.Evaluate(ctx, tc); err == nil {
		t.Fatal("Evaluate = nil, want require_email_verified error")
	}

	tc.EmailVerified = true
	if err := s.Evaluate(ctx, tc); err != nil {
		t.Fatalf("Evaluate = %v, want nil once EmailVerified=true", err)
	}
}
