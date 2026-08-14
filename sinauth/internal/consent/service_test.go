//go:build integration

package consent

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// These tests focus on Service.HasConsent's scope-matching semantics —
// the security-relevant logic of this package: does a previously granted
// consent correctly cover (or refuse to cover) a newly requested scope
// set. Getting this wrong in the "broader consent silently covers a
// different/narrower scope it was never asked about" direction would be
// relatively benign; getting it wrong in the other direction (a narrower
// grant is treated as covering a broader request) would let a client
// silently obtain access to scopes the user never consented to — an
// authorization bug.

func newTestService(t *testing.T) (*Service, string, string) {
	t.Helper()
	pool := requireDB(t)
	store := NewStore(pool)
	svc := NewService(store)

	userID := createTestUser(t, pool, fmt.Sprintf("svcuser%d", time.Now().UnixNano()))
	clientID := createTestClient(t, pool, fmt.Sprintf("svc-client-%d", time.Now().UnixNano()))
	return svc, userID, clientID
}

// TestHasConsent_NoPriorGrant_False proves a user/client pair with no
// consent history is correctly reported as not consented (fail closed).
func TestHasConsent_NoPriorGrant_False(t *testing.T) {
	svc, userID, clientID := newTestService(t)
	ctx := context.Background()

	ok, err := svc.HasConsent(ctx, userID, clientID, []string{"openid"})
	if err != nil {
		t.Fatalf("HasConsent: %v", err)
	}
	if ok {
		t.Fatal("HasConsent = true, want false with no prior grant")
	}
}

// TestHasConsent_ExactScopeMatch proves a consent granted for exactly the
// requested scopes is honored.
func TestHasConsent_ExactScopeMatch(t *testing.T) {
	svc, userID, clientID := newTestService(t)
	ctx := context.Background()

	if err := svc.Grant(ctx, userID, clientID, []string{"openid", "profile"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	ok, err := svc.HasConsent(ctx, userID, clientID, []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("HasConsent: %v", err)
	}
	if !ok {
		t.Fatal("HasConsent = false, want true for an exact scope match")
	}
}

// TestHasConsent_BroaderPriorGrant_CoversNarrowerRequest proves that if a
// user previously consented to a broader scope set, a later request for a
// subset of those scopes is correctly recognized as already consented
// (the user shouldn't be re-prompted for a strict subset of what they
// already agreed to).
func TestHasConsent_BroaderPriorGrant_CoversNarrowerRequest(t *testing.T) {
	svc, userID, clientID := newTestService(t)
	ctx := context.Background()

	if err := svc.Grant(ctx, userID, clientID, []string{"openid", "profile", "email"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	ok, err := svc.HasConsent(ctx, userID, clientID, []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("HasConsent: %v", err)
	}
	if !ok {
		t.Fatal("HasConsent = false, want true — a broader prior grant should cover a narrower request")
	}
}

// TestHasConsent_NarrowerPriorGrant_DoesNotCoverBroaderRequest is the
// security-critical direction: a user who previously granted only a
// narrow scope set must NOT be treated as having consented to a broader
// request that includes an ungranted scope. If this were silently
// treated as "consented", a client could later request additional scopes
// (e.g. escalate from "profile" to "profile,admin") and skip the consent
// prompt entirely.
func TestHasConsent_NarrowerPriorGrant_DoesNotCoverBroaderRequest(t *testing.T) {
	svc, userID, clientID := newTestService(t)
	ctx := context.Background()

	if err := svc.Grant(ctx, userID, clientID, []string{"openid"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	ok, err := svc.HasConsent(ctx, userID, clientID, []string{"openid", "profile"})
	if err != nil {
		t.Fatalf("HasConsent: %v", err)
	}
	if ok {
		t.Fatal("HasConsent = true, want false — prior grant did not include 'profile', must not be silently reused")
	}
}

// TestHasConsent_DisjointScopes_False proves a completely different scope
// set (no overlap at all) is not treated as consent.
func TestHasConsent_DisjointScopes_False(t *testing.T) {
	svc, userID, clientID := newTestService(t)
	ctx := context.Background()

	if err := svc.Grant(ctx, userID, clientID, []string{"openid"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	ok, err := svc.HasConsent(ctx, userID, clientID, []string{"admin"})
	if err != nil {
		t.Fatalf("HasConsent: %v", err)
	}
	if ok {
		t.Fatal("HasConsent = true, want false — 'admin' scope was never granted")
	}
}

// TestHasConsent_EmptyRequestedScopes_VacuouslyTrue documents that
// requesting zero scopes is vacuously satisfied even with no prior grant
// (the for-loop over an empty scopes slice never finds a missing scope).
// This mirrors normal "all elements of the empty set satisfy the
// predicate" semantics; call sites are expected to never invoke
// HasConsent with an empty requested-scope list for a real authorization
// decision, but this test pins the actual behavior down explicitly rather
// than leaving it as an implicit, untested assumption.
func TestHasConsent_EmptyRequestedScopes_VacuouslyTrue(t *testing.T) {
	svc, userID, clientID := newTestService(t)
	ctx := context.Background()

	ok, err := svc.HasConsent(ctx, userID, clientID, nil)
	if err != nil {
		t.Fatalf("HasConsent: %v", err)
	}
	if !ok {
		t.Fatal("HasConsent = false, want true (vacuous truth) for an empty requested-scopes list")
	}
}

// TestHasConsent_ScopedPerClient proves consent granted for one client
// does not leak into HasConsent checks for a different client — each
// OAuth client's consent must be isolated.
func TestHasConsent_ScopedPerClient(t *testing.T) {
	pool := requireDB(t)
	store := NewStore(pool)
	svc := NewService(store)
	ctx := context.Background()

	uniq := time.Now().UnixNano()
	userID := createTestUser(t, pool, fmt.Sprintf("multiclientuser%d", uniq))
	clientA := createTestClient(t, pool, fmt.Sprintf("client-a-%d", uniq))
	clientB := createTestClient(t, pool, fmt.Sprintf("client-b-%d", uniq))

	if err := svc.Grant(ctx, userID, clientA, []string{"openid", "profile"}); err != nil {
		t.Fatalf("Grant client A: %v", err)
	}

	ok, err := svc.HasConsent(ctx, userID, clientB, []string{"openid"})
	if err != nil {
		t.Fatalf("HasConsent client B: %v", err)
	}
	if ok {
		t.Fatal("HasConsent = true for client B, want false — consent for client A must not leak to client B")
	}
}

// TestRevoke_ClearsConsent proves Revoke actually removes the granted
// consent, so a subsequent HasConsent check (even for previously granted
// scopes) correctly returns false and the user is re-prompted.
func TestRevoke_ClearsConsent(t *testing.T) {
	svc, userID, clientID := newTestService(t)
	ctx := context.Background()

	if err := svc.Grant(ctx, userID, clientID, []string{"openid", "profile"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	ok, err := svc.HasConsent(ctx, userID, clientID, []string{"openid"})
	if err != nil || !ok {
		t.Fatalf("HasConsent before Revoke = (%v, %v), want (true, nil)", ok, err)
	}

	if err := svc.Revoke(ctx, userID, clientID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	ok, err = svc.HasConsent(ctx, userID, clientID, []string{"openid"})
	if err != nil {
		t.Fatalf("HasConsent after Revoke: %v", err)
	}
	if ok {
		t.Fatal("HasConsent = true after Revoke, want false")
	}
}
