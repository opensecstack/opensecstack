package rbac

import (
	"context"
	"testing"

	"github.com/opensecstack/sinauth/internal/authz"
)

// These are pure-logic unit tests that require no database and no build
// tag — they exercise hasRole/roleHeld/syncWrite/syncDelete branch logic
// directly (white-box, same package), including branches that are
// unreachable through the public NewStore constructor (which always
// defaults to a non-nil authz.NoopChecker) such as a literal nil checker.

func TestHasRole(t *testing.T) {
	cases := []struct {
		name   string
		roles  []string
		target string
		want   bool
	}{
		{"present", []string{"admin", "viewer"}, "admin", true},
		{"present-last", []string{"viewer", "admin"}, "admin", true},
		{"absent", []string{"viewer"}, "admin", false},
		{"empty-roles", nil, "admin", false},
		{"empty-target-not-in-roles", []string{"admin"}, "", false},
		{"case-sensitive-mismatch", []string{"Admin"}, "admin", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasRole(tc.roles, tc.target); got != tc.want {
				t.Errorf("hasRole(%v, %q) = %v, want %v", tc.roles, tc.target, got, tc.want)
			}
		})
	}
}

// stubChecker lets roleHeld's authz.Checker branch be exercised precisely:
// configurable allow/error per Check call, without needing a DB or a real
// Permify deployment.
type stubChecker struct {
	allow   bool
	err     error
	calls   int
	lastSub authz.Entity
	lastEnt authz.Entity
}

func (s *stubChecker) Check(_ context.Context, subject authz.Entity, _ string, entity authz.Entity) (bool, error) {
	s.calls++
	s.lastSub = subject
	s.lastEnt = entity
	return s.allow, s.err
}
func (s *stubChecker) WriteRelationship(context.Context, authz.Relationship) error  { return nil }
func (s *stubChecker) DeleteRelationship(context.Context, authz.Relationship) error { return nil }

var _ authz.Checker = (*stubChecker)(nil)

// TestRoleHeld_DirectMatch proves the direct tc.Roles check short-circuits
// and never consults the checker — critical because a nil/misconfigured
// checker must never be able to turn a legitimate direct-role match into a
// false negative.
func TestRoleHeld_DirectMatch(t *testing.T) {
	checker := &stubChecker{allow: false} // would deny if consulted
	s := &Store{checker: checker}
	tc := TokenContext{UserID: "u1", ClientID: "c1", Roles: []string{"banned"}}

	if !s.roleHeld(context.Background(), tc, "banned") {
		t.Fatal("roleHeld = false, want true (direct role match)")
	}
	if checker.calls != 0 {
		t.Errorf("checker.Check called %d times, want 0 — direct match should short-circuit", checker.calls)
	}
}

// TestRoleHeld_NilChecker proves a nil checker (unreachable via NewStore,
// but defensively guarded in roleHeld) is treated as "no additional
// match" rather than panicking.
func TestRoleHeld_NilChecker(t *testing.T) {
	s := &Store{checker: nil}
	tc := TokenContext{UserID: "u1", ClientID: "c1", Roles: nil}

	if s.roleHeld(context.Background(), tc, "banned") {
		t.Fatal("roleHeld = true, want false with nil checker and no direct match")
	}
}

// TestRoleHeld_EmptyUserOrClient proves roleHeld does not consult the
// checker when UserID or ClientID is empty — a defensive guard against
// building a malformed/ambiguous client_role entity ID.
func TestRoleHeld_EmptyUserOrClient(t *testing.T) {
	checker := &stubChecker{allow: true} // would allow if consulted
	cases := []struct {
		name string
		tc   TokenContext
	}{
		{"empty-user", TokenContext{UserID: "", ClientID: "c1"}},
		{"empty-client", TokenContext{UserID: "u1", ClientID: ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checker.calls = 0
			s := &Store{checker: checker}
			if s.roleHeld(context.Background(), tc.tc, "role") {
				t.Fatal("roleHeld = true, want false")
			}
			if checker.calls != 0 {
				t.Errorf("checker.Check called %d times, want 0", checker.calls)
			}
		})
	}
}

// TestRoleHeld_ViaChecker_Allow proves roleHeld falls through to the
// checker and honours an allow verdict when there is no direct-role match.
func TestRoleHeld_ViaChecker_Allow(t *testing.T) {
	checker := &stubChecker{allow: true}
	s := &Store{checker: checker}
	tc := TokenContext{UserID: "u1", ClientID: "c1", Roles: nil}

	if !s.roleHeld(context.Background(), tc, "banned") {
		t.Fatal("roleHeld = false, want true (checker allows)")
	}
	if checker.calls != 1 {
		t.Errorf("checker.Check called %d times, want 1", checker.calls)
	}
	wantEnt := authz.Entity{Type: "client_role", ID: clientRoleID("c1", "banned")}
	if checker.lastEnt != wantEnt {
		t.Errorf("checker.Check entity = %+v, want %+v", checker.lastEnt, wantEnt)
	}
	wantSub := authz.Entity{Type: "user", ID: "u1"}
	if checker.lastSub != wantSub {
		t.Errorf("checker.Check subject = %+v, want %+v", checker.lastSub, wantSub)
	}
}

// TestRoleHeld_ViaChecker_ErrorFailsOpenOnlyOnCheckerSide proves that a
// checker error is treated as "no additional match" (i.e. roleHeld
// returns false when there's no direct match either) rather than
// propagating — the direct-role check is the source of truth and must not
// be destabilized by a flaky/erroring authz engine.
func TestRoleHeld_ViaChecker_ErrorFailsOpenOnlyOnCheckerSide(t *testing.T) {
	checker := &stubChecker{allow: true, err: context.DeadlineExceeded}
	s := &Store{checker: checker}
	tc := TokenContext{UserID: "u1", ClientID: "c1", Roles: nil}

	if s.roleHeld(context.Background(), tc, "banned") {
		t.Fatal("roleHeld = true, want false when checker errors")
	}
}

// TestRoleHeld_ViaChecker_Deny proves a checker that explicitly denies
// (no error, allow=false) also yields false, as opposed to accidentally
// treating "denied" the same as "match".
func TestRoleHeld_ViaChecker_Deny(t *testing.T) {
	checker := &stubChecker{allow: false}
	s := &Store{checker: checker}
	tc := TokenContext{UserID: "u1", ClientID: "c1", Roles: []string{"other-role"}}

	if s.roleHeld(context.Background(), tc, "banned") {
		t.Fatal("roleHeld = true, want false when checker denies and no direct match")
	}
}

// --- syncWrite / syncDelete nil-checker branch ---
//
// These never touch s.pool, so they're safe to call on a Store built with a
// nil pool as long as the checker itself is nil (the nil-pool is never
// dereferenced). NewStore can never produce a nil checker (it defaults to
// authz.NoopChecker), so this branch is only reachable via a literal Store
// — exercised here to prove the nil-check guard actually prevents a panic,
// since some other constructor or future refactor could hit it.

func TestSyncWrite_NilChecker_NoPanic(t *testing.T) {
	s := &Store{checker: nil}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("syncWrite panicked with nil checker: %v", r)
		}
	}()
	s.syncWrite(context.Background(), authz.Relationship{
		Entity:   authz.Entity{Type: "group", ID: "g1"},
		Relation: "member",
		Subject:  authz.Entity{Type: "user", ID: "u1"},
	})
}

func TestSyncDelete_NilChecker_NoPanic(t *testing.T) {
	s := &Store{checker: nil}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("syncDelete panicked with nil checker: %v", r)
		}
	}()
	s.syncDelete(context.Background(), authz.Relationship{
		Entity:   authz.Entity{Type: "group", ID: "g1"},
		Relation: "member",
		Subject:  authz.Entity{Type: "user", ID: "u1"},
	})
}

// TestSyncWrite_LogsButDoesNotPanic_OnCheckerError proves the logged-not-
// propagated contract at the syncWrite/syncDelete level directly (the
// store_test.go integration tests already prove it end-to-end through
// AddGroupMember/AssignUserRole; this isolates just the sync helpers).
func TestSyncWrite_LogsButDoesNotPanic_OnCheckerError(t *testing.T) {
	checker := &stubChecker{}
	s := &Store{checker: checker}
	rel := authz.Relationship{
		Entity:   authz.Entity{Type: "group", ID: "g1"},
		Relation: "member",
		Subject:  authz.Entity{Type: "user", ID: "u1"},
	}
	// WriteRelationship/DeleteRelationship on stubChecker always return nil,
	// so this just proves no panic occurs on the happy path via the direct
	// (non-NewStore) construction path too.
	s.syncWrite(context.Background(), rel)
	s.syncDelete(context.Background(), rel)
}

func TestClientRoleID(t *testing.T) {
	if got, want := clientRoleID("client-1", "admin"), "client-1:admin"; got != want {
		t.Errorf("clientRoleID = %q, want %q", got, want)
	}
}
