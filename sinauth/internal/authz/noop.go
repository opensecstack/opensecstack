package authz

import "context"

// NoopChecker is the fallback Checker used when Permify is not configured
// (SINAUTH_PERMIFY_URL unset, i.e. cfg.PermifyEnabled == false) — mirroring
// mfa.NoopSMSProvider's real-vs-noop pattern.
//
// Check always allows: this preserves sinauth's behavior *before* Permify
// existed, where there was no per-resource authorization gate at all (only
// the flat RequireAdmin platform-admin check). It also matches the
// documented fail-open precedent in rbac.Store.Evaluate, which returns nil
// (allow) on a policy-lookup DB error rather than blocking legitimate
// logins — an authz.Checker that isn't wired to anything real should be
// equally permissive, not silently start denying everything.
//
// WriteRelationship/DeleteRelationship are no-ops: with no real engine
// behind them, there is nothing to keep in sync.
type NoopChecker struct{}

// NewNoopChecker constructs a NoopChecker.
func NewNoopChecker() *NoopChecker {
	return &NoopChecker{}
}

// Check always allows. See the NoopChecker doc comment for why this is the
// correct fail-open default, not a placeholder to "fix later".
func (NoopChecker) Check(ctx context.Context, subject Entity, permission string, entity Entity) (bool, error) {
	return true, nil
}

// WriteRelationship is a no-op.
func (NoopChecker) WriteRelationship(ctx context.Context, rel Relationship) error {
	return nil
}

// DeleteRelationship is a no-op.
func (NoopChecker) DeleteRelationship(ctx context.Context, rel Relationship) error {
	return nil
}

var _ Checker = NoopChecker{}
