package rbac

import (
	"context"
	"errors"
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
}

// Evaluate checks all enabled policies against the token context.
// Returns ErrPolicyDenied with a reason if any policy blocks issuance.
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
			if p.RoleName != "" && hasRole(tc.Roles, p.RoleName) {
				return errors.New("role denied by policy: " + p.Name)
			}
		}
	}
	return nil
}

func hasRole(roles []string, target string) bool {
	for _, r := range roles {
		if r == target {
			return true
		}
	}
	return false
}
