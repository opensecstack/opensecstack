package rbac

import (
	"context"
	"errors"

	"github.com/opensecstack/sinauth/internal/authz"
)

// ErrPolicyDenied is returned when a policy blocks token issuance.
var ErrPolicyDenied = errors.New("policy denied")

// TokenContext holds the state available during policy evaluation.
type TokenContext struct {
	UserID        string
	Username      string
	ClientID      string
	Roles         []string
	MFAVerified   bool
	EmailVerified bool
	// OrgID and OrgRole (ADR 005 v1.1) let policies be scoped to organization
	// context (e.g. "require_mfa" only when acting on behalf of a government
	// org). Not yet wired into Evaluate/its call sites — this is shape-only,
	// extending TokenContext ahead of the policy-evaluation work.
	OrgID   string
	OrgRole string
}

// Evaluate checks all enabled policies against the token context.
// Returns ErrPolicyDenied with a reason if any policy blocks issuance.
//
// deny_role policies additionally consult s.checker (the same authz.Checker
// Store was constructed with, for Permify write-through sync — see
// NewStore/syncWrite) via the client_role Permify entity: a role is treated
// as "held" for deny_role purposes if either the direct tc.Roles string
// check (unchanged, pre-existing behaviour) matches OR
// s.checker.Check(user, "use", client_role) reports true. This is purely
// additive — deny_role policies still work exactly as before even before
// Permify role-assignment tuples have been backfilled, and a nil checker or
// a checker error is treated as "no additional match" (fail open on the
// authz-engine side of the check only, never on the direct-role check).
func (s *Store) Evaluate(ctx context.Context, tc TokenContext) error {
	policies, err := s.ListPolicies(ctx)
	if err != nil {
		return nil // fail open on DB error for policy checks — don't block legitimate logins
	}

	for _, p := range policies {
		// Skip policies scoped to a different client.
		if p.ClientID != "" && p.ClientID != tc.ClientID {
			continue
		}

		switch p.Type {
		case "require_mfa":
			// If policy requires MFA for a specific role, check if user has that role.
			if p.RoleName == "" || hasRole(tc.Roles, p.RoleName) {
				if !tc.MFAVerified {
					return errors.New("MFA required: " + p.Name)
				}
			}
		case "require_email_verified":
			if !tc.EmailVerified {
				return errors.New("email verification required: " + p.Name)
			}
		case "deny_role":
			if p.RoleName != "" && s.roleHeld(ctx, tc, p.RoleName) {
				return errors.New("role denied by policy: " + p.Name)
			}
		}
	}
	return nil
}

// roleHeld reports whether tc's subject holds roleName for the purposes of
// a deny_role policy, checking both the existing direct-role-string match
// (tc.Roles, as populated by rbac.GetEffectiveRoles) and, additionally, the
// Permify "client_role.use" permission via s.checker — so deny_role policies
// take effect for roles granted purely through Permify relationship tuples,
// not only ones present in tc.Roles.
func (s *Store) roleHeld(ctx context.Context, tc TokenContext, roleName string) bool {
	if hasRole(tc.Roles, roleName) {
		return true
	}
	if s.checker == nil || tc.UserID == "" || tc.ClientID == "" {
		return false
	}
	allowed, err := s.checker.Check(ctx,
		authz.Entity{Type: "user", ID: tc.UserID},
		"use",
		authz.Entity{Type: "client_role", ID: clientRoleID(tc.ClientID, roleName)},
	)
	if err != nil {
		return false // fail open on authz-engine error — the direct check above already ran
	}
	return allowed
}

func hasRole(roles []string, target string) bool {
	for _, r := range roles {
		if r == target {
			return true
		}
	}
	return false
}
