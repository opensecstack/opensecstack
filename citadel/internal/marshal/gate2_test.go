package marshal

import (
	"context"
	"testing"
)

// ── Fake PermifySnapshot ─────────────────────────────────────────────────────

// fakePermifySnapshot is a minimal in-memory stand-in for
// internal/permifysync.Snapshot, keyed by "role|actionType".
type fakePermifySnapshot struct {
	entries map[string]bool // "role|actionType" -> allowed
}

func newFakePermifySnapshot() *fakePermifySnapshot {
	return &fakePermifySnapshot{entries: make(map[string]bool)}
}

func (f *fakePermifySnapshot) set(role, actionType string, allowed bool) *fakePermifySnapshot {
	f.entries[role+"|"+actionType] = allowed
	return f
}

func (f *fakePermifySnapshot) Allowed(role, actionType string) (allowed bool, known bool) {
	a, ok := f.entries[role+"|"+actionType]
	return a, ok
}

// ── Gate 2 / Permify combination tests ──────────────────────────────────────

// rbacMap pass + Permify unknown → PASS, exactly today's behavior,
// unaffected by wiring a (empty-for-this-role/action) snapshot in.
func TestGate2_RBACPass_PermifyUnknown_Pass(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	snap := newFakePermifySnapshot() // no opinion on operator/API_SCAN_INITIATE
	engine := New(store, verifier).PermifySnapshot(snap).EnforcePermifyAuthz(true)
	k := baseKerkese() // Actor.Role="operator", Action.Type="API_SCAN_INITIATE"
	signKerkese(k, opPriv, vfPriv)

	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[1].Status != GatePass {
		t.Errorf("gate2: expected PASS when Permify has no opinion, got %s: %s", d.Gates[1].Status, d.Gates[1].Reason)
	}
	if d.Outcome != OutcomeExecute {
		t.Errorf("expected EXECUTE, got %s", d.Outcome)
	}
}

// rbacMap pass + Permify known-deny + flag=false → WARN only, still
// EXECUTE for outcome purposes (the flag being off means Check B can never
// produce a FAIL via combineChecks).
func TestGate2_RBACPass_PermifyKnownDeny_FlagOff_WarnOnly(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	snap := newFakePermifySnapshot().set("operator", "API_SCAN_INITIATE", false)
	engine := New(store, verifier).PermifySnapshot(snap) // EnforcePermifyAuthz defaults false
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)

	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[1].Status != GateWarn {
		t.Errorf("gate2: expected WARN for Permify known-deny with flag off, got %s: %s", d.Gates[1].Status, d.Gates[1].Reason)
	}
	if d.Outcome != OutcomeExecute {
		t.Errorf("flag off: Permify known-deny must not block (rbacMap passed), got outcome %s", d.Outcome)
	}
}

// rbacMap pass + Permify known-deny + flag=true → FAIL/REFUSE.
func TestGate2_RBACPass_PermifyKnownDeny_FlagOn_Refuse(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	snap := newFakePermifySnapshot().set("operator", "API_SCAN_INITIATE", false)
	engine := New(store, verifier).PermifySnapshot(snap).EnforcePermifyAuthz(true)
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)

	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[1].Status != GateFail {
		t.Errorf("gate2: expected FAIL for Permify known-deny with flag on, got %s: %s", d.Gates[1].Status, d.Gates[1].Reason)
	}
	if d.Outcome != OutcomeRefuse {
		t.Errorf("flag on: Permify known-deny must REFUSE, got outcome %s", d.Outcome)
	}
}

// rbacMap fail, regardless of what Permify says (including an explicit
// known-allow) or whether the flag is set, must always FAIL/REFUSE — the
// safety net is never bypassed by Permify.
func TestGate2_RBACFail_AlwaysRefuses_RegardlessOfPermify(t *testing.T) {
	tests := []struct {
		name string
		snap *fakePermifySnapshot
		flag bool
	}{
		{"no snapshot, flag off", nil, false},
		{"no snapshot, flag on", nil, true},
		{"Permify known-allow, flag off", newFakePermifySnapshot().set("viewer", "API_SCAN_INITIATE", true), false},
		{"Permify known-allow, flag on", newFakePermifySnapshot().set("viewer", "API_SCAN_INITIATE", true), true},
		{"Permify unknown, flag on", newFakePermifySnapshot(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, verifier, opPriv, vfPriv := storeWithUsers("viewer", "analyst")
			engine := New(store, verifier).EnforcePermifyAuthz(tt.flag)
			if tt.snap != nil {
				engine = engine.PermifySnapshot(tt.snap)
			}
			k := baseKerkese()
			k.Actor.Role = "viewer" // not in rbacMap's allowed list for API_SCAN_INITIATE
			signKerkese(k, opPriv, vfPriv)

			d, err := engine.Evaluate(context.Background(), k)
			if err != nil {
				t.Fatal(err)
			}
			if d.Gates[1].Status != GateFail {
				t.Errorf("gate2: expected FAIL (rbacMap safety net), got %s: %s", d.Gates[1].Status, d.Gates[1].Reason)
			}
			if d.Outcome != OutcomeRefuse {
				t.Errorf("expected REFUSE, got %s", d.Outcome)
			}
		})
	}
}

// Regression: a role/action pair entirely absent from rbacMap (unknown
// role) still fails closed exactly as before, even when Permify also has
// no opinion — absence of data from BOTH sources must still deny, not
// default-allow.
func TestGate2_UnknownRole_FailsClosed_EvenWithPermifyUnknown(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("contractor", "analyst") // "contractor" is not a rbacMap key at all
	snap := newFakePermifySnapshot()                                          // no opinion either
	engine := New(store, verifier).PermifySnapshot(snap).EnforcePermifyAuthz(true)
	k := baseKerkese()
	k.Actor.Role = "contractor"
	signKerkese(k, opPriv, vfPriv)

	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[1].Status != GateFail {
		t.Errorf("gate2: expected FAIL for role absent from rbacMap, got %s: %s", d.Gates[1].Status, d.Gates[1].Reason)
	}
	if d.Outcome != OutcomeRefuse {
		t.Errorf("expected REFUSE for unknown role with no Permify opinion, got %s", d.Outcome)
	}
}

// A nil (never-wired) PermifySnapshot behaves identically to a
// known-nothing snapshot: Gate 2 outcome depends only on rbacMap.
func TestGate2_NilSnapshot_BehavesLikeUnknown(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforcePermifyAuthz(true) // flag on, but no snapshot wired
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)

	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[1].Status != GatePass {
		t.Errorf("gate2: expected PASS with nil snapshot, got %s: %s", d.Gates[1].Status, d.Gates[1].Reason)
	}
	if d.Outcome != OutcomeExecute {
		t.Errorf("expected EXECUTE, got %s", d.Outcome)
	}
}
