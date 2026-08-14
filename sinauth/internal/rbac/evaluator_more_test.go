//go:build integration

package rbac

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestEvaluate_RequireMFA_Unscoped_AppliesToEveryone proves a require_mfa
// policy with no RoleName gates ALL logins for the client, not just a
// specific role — the empty-RoleName branch of the require_mfa case.
func TestEvaluate_RequireMFA_Unscoped_AppliesToEveryone(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	clientID := fmt.Sprintf("mfa-unscoped-%d", time.Now().UnixNano())
	createPolicy(t, s, Policy{Name: fmt.Sprintf("mfa-all-%d", time.Now().UnixNano()), Type: "require_mfa", ClientID: clientID})

	tc := TokenContext{UserID: "u1", ClientID: clientID, Roles: []string{"anyone"}, MFAVerified: false}
	if err := s.Evaluate(ctx, tc); err == nil {
		t.Fatal("Evaluate = nil, want MFA-required error for unscoped require_mfa policy")
	}

	tc.MFAVerified = true
	if err := s.Evaluate(ctx, tc); err != nil {
		t.Fatalf("Evaluate = %v, want nil once MFAVerified=true", err)
	}
}

// TestEvaluate_RequireMFA_ScopedToRole proves a require_mfa policy scoped
// to a specific RoleName only blocks users holding that role — a user
// without the role must not be forced through MFA by a policy that
// doesn't apply to them (and, critically, a user WITH the role must not
// bypass MFA).
func TestEvaluate_RequireMFA_ScopedToRole(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	clientID := fmt.Sprintf("mfa-scoped-%d", time.Now().UnixNano())
	createPolicy(t, s, Policy{
		Name: fmt.Sprintf("mfa-admin-only-%d", time.Now().UnixNano()),
		Type: "require_mfa", ClientID: clientID, RoleName: "admin",
	})

	// Non-admin, no MFA: must pass — policy doesn't apply to this role.
	tc := TokenContext{UserID: "u1", ClientID: clientID, Roles: []string{"viewer"}, MFAVerified: false}
	if err := s.Evaluate(ctx, tc); err != nil {
		t.Fatalf("Evaluate = %v, want nil for non-admin role without MFA", err)
	}

	// Admin, no MFA: must block.
	tc = TokenContext{UserID: "u2", ClientID: clientID, Roles: []string{"admin"}, MFAVerified: false}
	if err := s.Evaluate(ctx, tc); err == nil {
		t.Fatal("Evaluate = nil, want MFA-required error for admin role without MFA")
	}

	// Admin, with MFA: must pass.
	tc.MFAVerified = true
	if err := s.Evaluate(ctx, tc); err != nil {
		t.Fatalf("Evaluate = %v, want nil for admin with MFA verified", err)
	}
}

// TestEvaluate_PolicyScopedToDifferentClient_DoesNotApply proves the
// client-scoping guard at the top of Evaluate's policy loop: a policy
// scoped to ClientID X must never affect token issuance for client Y, even
// if the role/condition would otherwise match. A bug here would let one
// OAuth client's security policy silently leak into another client's
// login flow (or, worse, fail to enforce its own).
func TestEvaluate_PolicyScopedToDifferentClient_DoesNotApply(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	policyClientID := fmt.Sprintf("policy-client-%d", time.Now().UnixNano())
	otherClientID := fmt.Sprintf("other-client-%d", time.Now().UnixNano())
	createPolicy(t, s, Policy{
		Name: fmt.Sprintf("deny-elsewhere-%d", time.Now().UnixNano()),
		Type: "deny_role", ClientID: policyClientID, RoleName: "banned",
	})

	// Same banned role, but token is for a DIFFERENT client — must not be denied.
	tc := TokenContext{UserID: "u1", ClientID: otherClientID, Roles: []string{"banned"}}
	if err := s.Evaluate(ctx, tc); err != nil {
		t.Fatalf("Evaluate = %v, want nil — deny_role policy is scoped to a different client", err)
	}

	// Sanity: the same role IS denied for the client the policy actually targets.
	tc.ClientID = policyClientID
	if err := s.Evaluate(ctx, tc); err == nil {
		t.Fatal("Evaluate = nil, want deny_role error when ClientID matches the policy's scope")
	}
}

// TestEvaluate_GlobalPolicy_AppliesToAllClients proves a policy with an
// empty ClientID (global) applies regardless of which client is issuing
// the token.
func TestEvaluate_GlobalPolicy_AppliesToAllClients(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	roleName := fmt.Sprintf("globally-banned-%d", time.Now().UnixNano())
	createPolicy(t, s, Policy{
		Name: fmt.Sprintf("deny-global-%d", time.Now().UnixNano()),
		Type: "deny_role", ClientID: "", RoleName: roleName,
	})

	for _, clientID := range []string{"client-a", "client-b"} {
		tc := TokenContext{UserID: "u1", ClientID: clientID, Roles: []string{roleName}}
		if err := s.Evaluate(ctx, tc); err == nil {
			t.Fatalf("Evaluate for client %q = nil, want global deny_role error", clientID)
		}
	}
}

// TestEvaluate_DisabledPolicy_NotEnforced proves ListPolicies' WHERE
// enabled=true filter is actually load-bearing: creating a policy and
// then disabling it (enabled=false) must stop it from being enforced.
func TestEvaluate_DisabledPolicy_NotEnforced(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	clientID := fmt.Sprintf("disabled-policy-client-%d", time.Now().UnixNano())
	id := createPolicy(t, s, Policy{
		Name: fmt.Sprintf("deny-then-disable-%d", time.Now().UnixNano()),
		Type: "deny_role", ClientID: clientID, RoleName: "banned",
	})

	tc := TokenContext{UserID: "u1", ClientID: clientID, Roles: []string{"banned"}}
	if err := s.Evaluate(ctx, tc); err == nil {
		t.Fatal("Evaluate = nil, want deny_role error while policy enabled")
	}

	if _, err := pool.Exec(ctx, `UPDATE policies SET enabled=false WHERE id=$1`, id); err != nil {
		t.Fatalf("disable policy: %v", err)
	}

	if err := s.Evaluate(ctx, tc); err != nil {
		t.Fatalf("Evaluate = %v, want nil once policy is disabled", err)
	}
}

// TestEvaluate_UnimplementedPolicyType_FailsClosed documents the fix for a
// real gap found while writing these tests: the `policies` table's CHECK
// constraint (migrations/012_rbac.sql) allows type='allow_client' as a
// fourth policy type, presumably meant to restrict which clients a
// role/user may obtain tokens for (an allow-list, the inverse of
// deny_role). But (*Store).Evaluate's switch statement previously only
// handled "require_mfa", "require_email_verified", and "deny_role" —
// "allow_client" fell through with no case and was silently ignored,
// meaning an operator who created an allow_client policy believing it
// restricted token issuance got no enforcement at all. That was a
// fail-open silent gap in a security policy engine, not merely an unused
// feature: the schema advertised the capability (and CreatePolicy happily
// accepted it) but the enforcement path was never implemented.
//
// Implementing real allow-list semantics for allow_client is a product
// decision (what exactly it means re: ClientID/RoleName scoping) outside
// the scope of this fix. Instead, Evaluate's switch now has a default case
// that refuses token issuance for ANY policy type it doesn't implement,
// converting the silent fail-open into a loud, fail-closed error — an
// enabled-but-unenforceable policy blocks issuance rather than pretending
// to protect something it doesn't.
func TestEvaluate_UnimplementedPolicyType_FailsClosed(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	clientID := fmt.Sprintf("allow-client-gap-%d", time.Now().UnixNano())
	createPolicy(t, s, Policy{
		Name: fmt.Sprintf("allow-client-policy-%d", time.Now().UnixNano()),
		Type: "allow_client", ClientID: clientID, RoleName: "some-role",
	})

	tc := TokenContext{UserID: "u1", ClientID: clientID, Roles: []string{"some-role"}}
	if err := s.Evaluate(ctx, tc); err == nil {
		t.Fatal("Evaluate = nil, want an error — an unimplemented-but-enabled policy type must fail closed, not silently no-op")
	}
}
