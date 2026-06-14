package marshal

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ── Mock Store ───────────────────────────────────────────────────────────────

type mockStore struct {
	sessions     map[int64]mockSession
	actionCounts map[int64]int
	wormEntries  []*WORMEntry
}

type mockSession struct {
	role      string
	roleGroup string
}

func newMockStore() *mockStore {
	return &mockStore{
		sessions:     make(map[int64]mockSession),
		actionCounts: make(map[int64]int),
	}
}

func (m *mockStore) SessionExists(_ context.Context, userID int64) (role, group string, exists bool, err error) {
	s, ok := m.sessions[userID]
	if !ok {
		return "", "", false, nil
	}
	return s.role, s.roleGroup, true, nil
}

func (m *mockStore) ActionCount(_ context.Context, userID int64, _ time.Duration) (int, error) {
	return m.actionCounts[userID], nil
}

func (m *mockStore) AppendWORM(_ context.Context, _, _, _ string, _ []byte) (*WORMEntry, error) {
	e := &WORMEntry{
		ID:          uuid.New(),
		SequenceNum: int64(len(m.wormEntries) + 1),
		ChainHash:   "mock_chain_hash",
	}
	m.wormEntries = append(m.wormEntries, e)
	return e, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func baseKerkese() *Kerkese {
	return &Kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Date(2026, 4, 5, 10, 0, 0, 0, time.UTC), // 10:00 UTC — business hours
		ProjectID:      "test",
		ExecutionID:    uuid.New(),
		Action: KerkeseAction{
			Type:        "API_SCAN_INITIATE",
			Description: "test scan",
		},
		Actor:    KerkeseActor{UserID: 1, Role: "operator"},
		Verifier: KerkeseVerifier{UserID: 2, Role: "analyst"},
		SoD:      KerkeseSoD{OperatorUserID: 1, VerifierUserID: 2},
	}
}

func storeWithUsers(operatorRole, verifierRole string) *mockStore {
	s := newMockStore()
	s.sessions[1] = mockSession{role: operatorRole, roleGroup: roleGroup(operatorRole)}
	s.sessions[2] = mockSession{role: verifierRole, roleGroup: roleGroup(verifierRole)}
	return s
}

// ── Gate 1 Tests ─────────────────────────────────────────────────────────────

func TestGate1_Pass(t *testing.T) {
	store := storeWithUsers("operator", "analyst")
	engine := New(store)
	d, err := engine.Evaluate(context.Background(), baseKerkese())
	if err != nil {
		t.Fatal(err)
	}
	g1 := d.Gates[0]
	if g1.Status != GatePass {
		t.Errorf("gate1: expected PASS, got %s: %s", g1.Status, g1.Reason)
	}
}

func TestGate1_Fail_NoSession(t *testing.T) {
	store := newMockStore() // no sessions
	engine := New(store)
	d, err := engine.Evaluate(context.Background(), baseKerkese())
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != OutcomeRefuse {
		t.Errorf("expected REFUSE, got %s", d.Outcome)
	}
	if d.Gates[0].Status != GateFail {
		t.Errorf("gate1: expected FAIL, got %s", d.Gates[0].Status)
	}
}

func TestGate1_Fail_RoleMismatch(t *testing.T) {
	store := newMockStore()
	store.sessions[1] = mockSession{role: "admin", roleGroup: "privileged"}
	store.sessions[2] = mockSession{role: "analyst", roleGroup: "standard"}
	engine := New(store)
	k := baseKerkese()
	k.Actor.Role = "operator" // claims operator but session says admin
	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[0].Status != GateFail {
		t.Errorf("gate1: expected FAIL on role mismatch, got %s", d.Gates[0].Status)
	}
}

// ── Gate 2 Tests ─────────────────────────────────────────────────────────────

func TestGate2_Pass(t *testing.T) {
	store := storeWithUsers("operator", "analyst")
	engine := New(store)
	d, _ := engine.Evaluate(context.Background(), baseKerkese())
	if d.Gates[1].Status != GatePass {
		t.Errorf("gate2: expected PASS, got %s: %s", d.Gates[1].Status, d.Gates[1].Reason)
	}
}

func TestGate2_Fail_NotPermitted(t *testing.T) {
	store := storeWithUsers("viewer", "analyst")
	engine := New(store)
	k := baseKerkese()
	k.Actor.Role = "viewer"
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[1].Status != GateFail {
		t.Errorf("gate2: expected FAIL for viewer attempting scan, got %s", d.Gates[1].Status)
	}
	if d.Outcome != OutcomeRefuse {
		t.Errorf("expected REFUSE, got %s", d.Outcome)
	}
}

// ── Gate 3 Tests ─────────────────────────────────────────────────────────────

func TestGate3_Pass(t *testing.T) {
	store := storeWithUsers("operator", "analyst") // privileged vs standard
	engine := New(store)
	d, _ := engine.Evaluate(context.Background(), baseKerkese())
	if d.Gates[2].Status != GatePass {
		t.Errorf("gate3: expected PASS, got %s: %s", d.Gates[2].Status, d.Gates[2].Reason)
	}
}

func TestGate3_HardStop_SameIdentity(t *testing.T) {
	store := storeWithUsers("operator", "analyst")
	engine := New(store)
	k := baseKerkese()
	k.SoD.VerifierUserID = k.SoD.OperatorUserID // same user
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[2].Status != GateHardStop {
		t.Errorf("gate3: expected HARD_STOP for same identity, got %s", d.Gates[2].Status)
	}
	if d.Outcome != OutcomeHardStop {
		t.Errorf("expected HARD_STOP outcome, got %s", d.Outcome)
	}
}

func TestGate3_HardStop_SameGroup(t *testing.T) {
	store := newMockStore()
	store.sessions[1] = mockSession{role: "admin", roleGroup: "privileged"}
	store.sessions[2] = mockSession{role: "operator", roleGroup: "privileged"} // same group!
	engine := New(store)
	k := baseKerkese()
	k.Actor.Role = "admin"
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[2].Status != GateHardStop {
		t.Errorf("gate3: expected HARD_STOP for same role group, got %s", d.Gates[2].Status)
	}
}

// ── Gate 4 Tests ─────────────────────────────────────────────────────────────

func TestGate4_Pass_BusinessHours(t *testing.T) {
	store := storeWithUsers("operator", "analyst")
	engine := New(store)
	k := baseKerkese()
	k.TsUTC = time.Date(2026, 4, 5, 10, 0, 0, 0, time.UTC) // 10:00 UTC
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[3].Status != GatePass {
		t.Errorf("gate4: expected PASS during business hours, got %s: %s", d.Gates[3].Status, d.Gates[3].Reason)
	}
}

func TestGate4_Warn_OffHours(t *testing.T) {
	store := storeWithUsers("operator", "analyst")
	engine := New(store)
	k := baseKerkese()
	k.TsUTC = time.Date(2026, 4, 5, 2, 0, 0, 0, time.UTC) // 02:00 UTC — off-hours
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[3].Status != GateWarn {
		t.Errorf("gate4: expected WARN for off-hours, got %s", d.Gates[3].Status)
	}
	// WARN does not block execution
	if d.Outcome == OutcomeRefuse || d.Outcome == OutcomeHardStop {
		t.Errorf("gate4 WARN should not block; outcome=%s", d.Outcome)
	}
}

func TestGate4_HardStop_DataExportNoIncident(t *testing.T) {
	store := storeWithUsers("operator", "auditor")
	engine := New(store)
	k := baseKerkese()
	k.Actor.Role = "operator"
	k.Verifier.Role = "auditor"
	k.SoD.VerifierUserID = 2
	store.sessions[2] = mockSession{role: "auditor", roleGroup: "oversight"}
	k.Action.Type = "DATA_EXPORT"
	k.Action.IncidentID = "" // missing incident_id → HARD_STOP
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[3].Status != GateHardStop {
		t.Errorf("gate4: expected HARD_STOP for DATA_EXPORT without incident_id, got %s", d.Gates[3].Status)
	}
	if d.Outcome != OutcomeHardStop {
		t.Errorf("expected HARD_STOP outcome, got %s", d.Outcome)
	}
}

func TestGate4_Pass_DataExportWithIncident(t *testing.T) {
	store := storeWithUsers("operator", "auditor")
	store.sessions[2] = mockSession{role: "auditor", roleGroup: "oversight"}
	engine := New(store)
	k := baseKerkese()
	k.Actor.Role = "operator"
	k.Action.Type = "DATA_EXPORT"
	k.Action.IncidentID = "INC-2026-001" // provided → allowed
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[3].Status == GateHardStop {
		t.Errorf("gate4: DATA_EXPORT with incident_id should not HARD_STOP")
	}
}

// ── Gate 5 Tests ─────────────────────────────────────────────────────────────

func TestGate5_AlwaysWritesWORM(t *testing.T) {
	store := storeWithUsers("operator", "analyst")
	engine := New(store)

	// Even a REFUSE decision must produce a WORM entry
	k := baseKerkese()
	k.Actor.Role = "viewer" // will be refused at gate 2
	store.sessions[1] = mockSession{role: "viewer", roleGroup: "standard"}

	d, _ := engine.Evaluate(context.Background(), k)
	if d.Outcome != OutcomeRefuse {
		t.Errorf("expected REFUSE, got %s", d.Outcome)
	}
	if d.WORMEntryID == nil {
		t.Error("gate5: WORM entry must be written even on REFUSE")
	}
	if len(store.wormEntries) != 1 {
		t.Errorf("expected 1 WORM entry, got %d", len(store.wormEntries))
	}
}

func TestGate5_WORMEntry_OnHardStop(t *testing.T) {
	store := storeWithUsers("operator", "analyst")
	engine := New(store)
	k := baseKerkese()
	k.SoD.VerifierUserID = k.SoD.OperatorUserID // triggers HARD_STOP at gate 3
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Outcome != OutcomeHardStop {
		t.Errorf("expected HARD_STOP, got %s", d.Outcome)
	}
	if d.WORMEntryID == nil {
		t.Error("gate5: WORM entry must be written even on HARD_STOP")
	}
}

// ── Full Decision Tests ───────────────────────────────────────────────────────

func TestEvaluate_Execute_AllGatesPass(t *testing.T) {
	store := storeWithUsers("operator", "analyst")
	engine := New(store)
	d, err := engine.Evaluate(context.Background(), baseKerkese())
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != OutcomeExecute {
		t.Errorf("expected EXECUTE, got %s — reasons: %v", d.Outcome, d.Reasons)
	}
	if len(d.Gates) != 5 {
		t.Errorf("expected 5 gate results, got %d", len(d.Gates))
	}
	if d.WORMEntryID == nil {
		t.Error("EXECUTE decision must have a WORM entry ID")
	}
}

func TestEvaluate_DryRun_NoBlock(t *testing.T) {
	store := newMockStore() // no sessions → gate1 fails
	engine := New(store)
	k := baseKerkese()
	k.DryRun = true
	d, _ := engine.Evaluate(context.Background(), k)
	if !d.DryRun {
		t.Error("dry_run flag must be preserved in Decision")
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkMARSHAL_Evaluate(b *testing.B) {
	store := storeWithUsers("operator", "analyst")
	engine := New(store)
	k := baseKerkese()
	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.ExecutionID = uuid.New()
		_, _ = engine.Evaluate(ctx, k)
	}
}
