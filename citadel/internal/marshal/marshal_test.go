package marshal

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ── Mock Store ───────────────────────────────────────────────────────────────

type mockStore struct {
	actionCounts map[string]int
	wormEntries  []*WORMEntry
	keys         map[string]ed25519.PublicKey
}

func newMockStore() *mockStore {
	return &mockStore{
		actionCounts: make(map[string]int),
		keys:         make(map[string]ed25519.PublicKey),
	}
}

func (m *mockStore) ActionCount(_ context.Context, userID string, _ time.Duration) (int, error) {
	return m.actionCounts[userID], nil
}

func (m *mockStore) AppendWORM(_ context.Context, _, _, _ string, _ []byte, sigOperator, sigVerifier string) (*WORMEntry, error) {
	e := &WORMEntry{
		ID:          uuid.New(),
		SequenceNum: int64(len(m.wormEntries) + 1),
		ChainHash:   "mock_chain_hash",
		SigOperator: sigOperator,
		SigVerifier: sigVerifier,
	}
	m.wormEntries = append(m.wormEntries, e)
	return e, nil
}

func (m *mockStore) GetSigningKey(_ context.Context, userID string) (ed25519.PublicKey, bool, error) {
	pub, ok := m.keys[userID]
	if !ok {
		return nil, false, nil
	}
	return pub, true, nil
}

// ── Mock TokenVerifier ───────────────────────────────────────────────────────

var errNoSuchToken = errors.New("mock: no such token")

type mockTokenVerifier struct {
	tokens map[string]struct{ userID, role string }
}

func newMockTokenVerifier() *mockTokenVerifier {
	return &mockTokenVerifier{tokens: make(map[string]struct{ userID, role string })}
}

func (v *mockTokenVerifier) register(token, userID, role string) {
	v.tokens[token] = struct{ userID, role string }{userID, role}
}

func (v *mockTokenVerifier) Verify(_ context.Context, token string) (string, string, error) {
	t, ok := v.tokens[token]
	if !ok {
		return "", "", errNoSuchToken
	}
	return t.userID, t.role, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const (
	operatorUserID = "1"
	verifierUserID = "2"
	operatorToken  = "actor-token-1"
	verifierToken  = "verifier-token-2"
)

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
		Actor:    KerkeseActor{UserID: operatorUserID, Role: "operator"},
		Verifier: KerkeseVerifier{UserID: verifierUserID, Role: "analyst"},
		SoD:      KerkeseSoD{OperatorUserID: operatorUserID, VerifierUserID: verifierUserID},
	}
}

// storeWithUsers registers a valid token + signing key for operatorUserID
// and verifierUserID, returning the store, verifier, and private keys so
// tests can produce a validly-signed, validly-authenticated Kerkese via
// signKerkese.
func storeWithUsers(operatorRole, verifierRole string) (*mockStore, *mockTokenVerifier, ed25519.PrivateKey, ed25519.PrivateKey) {
	s := newMockStore()
	v := newMockTokenVerifier()
	v.register(operatorToken, operatorUserID, operatorRole)
	v.register(verifierToken, verifierUserID, verifierRole)

	opPub, opPriv, _ := ed25519.GenerateKey(nil)
	vfPub, vfPriv, _ := ed25519.GenerateKey(nil)
	s.keys[operatorUserID] = opPub
	s.keys[verifierUserID] = vfPub
	return s, v, opPriv, vfPriv
}

// signKerkese signs k with the given operator/verifier private keys and
// attaches the matching bearer tokens, mirroring sdk/go/citadel.Sign plus
// the ActorToken/VerifierToken producers must forward.
func signKerkese(k *Kerkese, opPriv, vfPriv ed25519.PrivateKey) {
	payload := []byte(CanonicalPayload(*k))
	k.SigOperator = hex.EncodeToString(ed25519.Sign(opPriv, payload))
	k.SigVerifier = hex.EncodeToString(ed25519.Sign(vfPriv, payload))
	k.ActorToken = operatorToken
	k.VerifierToken = verifierToken
}

// ── Gate 1 Tests ─────────────────────────────────────────────────────────────

func TestGate1_Pass(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)
	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	g1 := d.Gates[0]
	if g1.Status != GatePass {
		t.Errorf("gate1: expected PASS, got %s: %s", g1.Status, g1.Reason)
	}
}

func TestGate1_Warn_NoToken_SoftMode(t *testing.T) {
	store, verifier, _, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)                                 // soft mode: identity checks warn, don't block
	d, err := engine.Evaluate(context.Background(), baseKerkese()) // no ActorToken
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != OutcomeExecute {
		t.Errorf("soft mode: missing token must not block, got outcome %s", d.Outcome)
	}
	if d.Gates[0].Status != GateWarn {
		t.Errorf("gate1: expected WARN, got %s", d.Gates[0].Status)
	}
}

func TestGate1_Fail_NoToken_EnforcedMode(t *testing.T) {
	store, verifier, _, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforceIdentity(true)
	d, err := engine.Evaluate(context.Background(), baseKerkese()) // no ActorToken
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

func TestGate1_Fail_InvalidToken_EnforcedMode(t *testing.T) {
	store, verifier, _, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforceIdentity(true)
	k := baseKerkese()
	k.ActorToken = "not-a-real-token"
	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[0].Status != GateFail {
		t.Errorf("gate1: expected FAIL for invalid token, got %s", d.Gates[0].Status)
	}
}

func TestGate1_Fail_TokenSubjectMismatch_EnforcedMode(t *testing.T) {
	store, verifier, _, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforceIdentity(true)
	k := baseKerkese()
	k.ActorToken = verifierToken // valid token, but for the wrong user
	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[0].Status != GateFail {
		t.Errorf("gate1: expected FAIL on token/actor mismatch, got %s", d.Gates[0].Status)
	}
}

func TestGate1_Warn_MissingSignature_SoftMode(t *testing.T) {
	store, verifier, _, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier) // enforceSignatures defaults to false
	k := baseKerkese()
	k.ActorToken = operatorToken // authenticated, but unsigned
	k.VerifierToken = verifierToken
	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[0].Status != GateWarn {
		t.Errorf("gate1: expected WARN for missing signature in soft mode, got %s: %s", d.Gates[0].Status, d.Gates[0].Reason)
	}
	if d.Outcome != OutcomeExecute {
		t.Errorf("soft mode: missing signature must not block, got outcome %s", d.Outcome)
	}
}

func TestGate1_Fail_MissingSignature_EnforcedMode(t *testing.T) {
	store, verifier, _, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforceSignatures(true)
	k := baseKerkese()
	k.ActorToken = operatorToken
	k.VerifierToken = verifierToken
	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[0].Status != GateFail {
		t.Errorf("gate1: expected FAIL for missing signature in enforced mode, got %s", d.Gates[0].Status)
	}
	if d.Outcome != OutcomeRefuse {
		t.Errorf("enforced mode: missing signature must REFUSE, got outcome %s", d.Outcome)
	}
}

func TestGate1_Fail_TamperedSignature_EnforcedMode(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforceSignatures(true)
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)
	k.Action.Type = "API_SCAN_DELETE" // mutate payload after signing

	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[0].Status != GateFail {
		t.Errorf("gate1: expected FAIL for tampered payload, got %s", d.Gates[0].Status)
	}
}

func TestGate1_Fail_UnregisteredKey_EnforcedMode(t *testing.T) {
	store, verifier, _, _ := storeWithUsers("operator", "analyst")
	delete(store.keys, operatorUserID) // authenticated, but no signing key registered
	_, opPriv, _ := ed25519.GenerateKey(nil)
	_, vfPriv, _ := ed25519.GenerateKey(nil)
	engine := New(store, verifier).EnforceSignatures(true)
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)

	d, err := engine.Evaluate(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if d.Gates[0].Status != GateFail {
		t.Errorf("gate1: expected FAIL for unregistered signing key, got %s", d.Gates[0].Status)
	}
}

// ── Gate 2 Tests ─────────────────────────────────────────────────────────────

func TestGate2_Pass(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[1].Status != GatePass {
		t.Errorf("gate2: expected PASS, got %s: %s", d.Gates[1].Status, d.Gates[1].Reason)
	}
}

func TestGate2_Fail_NotPermitted(t *testing.T) {
	store, verifier, _, _ := storeWithUsers("viewer", "analyst")
	engine := New(store, verifier)
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
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst") // privileged vs standard
	engine := New(store, verifier)
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[2].Status != GatePass {
		t.Errorf("gate3: expected PASS, got %s: %s", d.Gates[2].Status, d.Gates[2].Reason)
	}
}

func TestGate3_HardStop_SameIdentity(t *testing.T) {
	store, verifier, opPriv, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)
	k := baseKerkese()
	k.SoD.VerifierUserID = k.SoD.OperatorUserID // same user
	k.Verifier.UserID = k.Actor.UserID
	signKerkese(k, opPriv, opPriv)
	k.VerifierToken = operatorToken
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[2].Status != GateHardStop {
		t.Errorf("gate3: expected HARD_STOP for same identity, got %s", d.Gates[2].Status)
	}
	if d.Outcome != OutcomeHardStop {
		t.Errorf("expected HARD_STOP outcome, got %s", d.Outcome)
	}
}

func TestGate3_HardStop_SameGroup(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("admin", "operator") // both "privileged"
	engine := New(store, verifier)
	k := baseKerkese()
	k.Actor.Role = "admin"
	k.Verifier.Role = "operator"
	signKerkese(k, opPriv, vfPriv)
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[2].Status != GateHardStop {
		t.Errorf("gate3: expected HARD_STOP for same role group, got %s", d.Gates[2].Status)
	}
}

func TestGate3_Fail_NoVerifierToken_EnforcedMode(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforceIdentity(true) // identity enforced, signatures not
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv) // both signatures valid — isolates the token check
	k.VerifierToken = ""           // operator authenticated, verifier is not
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[2].Status != GateFail {
		t.Errorf("gate3: expected FAIL for missing verifier_token, got %s", d.Gates[2].Status)
	}
}

func TestGate1_EnforceIdentityAlone_DoesNotBlockOnMissingSignature(t *testing.T) {
	store, verifier, _, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforceIdentity(true) // signatures NOT enforced
	k := baseKerkese()
	k.ActorToken = operatorToken
	k.VerifierToken = verifierToken // both tokens valid, no signatures at all
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[0].Status != GateWarn {
		t.Errorf("gate1: EnforceIdentity alone must not FAIL on a missing signature, got %s: %s", d.Gates[0].Status, d.Gates[0].Reason)
	}
	if d.Outcome != OutcomeExecute {
		t.Errorf("EnforceIdentity alone: missing signature must not block, got outcome %s", d.Outcome)
	}
}

func TestGate1_EnforceSignaturesAlone_DoesNotBlockOnMissingToken(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforceSignatures(true) // identity NOT enforced
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)
	k.ActorToken = "" // valid signature, but no token at all
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[0].Status != GateWarn {
		t.Errorf("gate1: EnforceSignatures alone must not FAIL on a missing token, got %s: %s", d.Gates[0].Status, d.Gates[0].Reason)
	}
	if d.Outcome != OutcomeExecute {
		t.Errorf("EnforceSignatures alone: missing token must not block, got outcome %s", d.Outcome)
	}
}

func TestGate3_Warn_MissingVerifierSignature_SoftMode(t *testing.T) {
	store, verifier, opPriv, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)
	k := baseKerkese()
	k.ActorToken = operatorToken
	k.VerifierToken = verifierToken
	// Only the operator signs — verifier signature left empty.
	payload := []byte(CanonicalPayload(*k))
	k.SigOperator = hex.EncodeToString(ed25519.Sign(opPriv, payload))

	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[2].Status != GateWarn {
		t.Errorf("gate3: expected WARN for missing verifier signature in soft mode, got %s: %s", d.Gates[2].Status, d.Gates[2].Reason)
	}
}

func TestGate3_Fail_MissingVerifierSignature_EnforcedMode(t *testing.T) {
	store, verifier, opPriv, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforceSignatures(true)
	k := baseKerkese()
	k.ActorToken = operatorToken
	k.VerifierToken = verifierToken
	payload := []byte(CanonicalPayload(*k))
	k.SigOperator = hex.EncodeToString(ed25519.Sign(opPriv, payload))

	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[2].Status != GateFail {
		t.Errorf("gate3: expected FAIL for missing verifier signature in enforced mode, got %s", d.Gates[2].Status)
	}
	if d.Outcome != OutcomeRefuse {
		t.Errorf("enforced mode: missing verifier signature must REFUSE, got outcome %s", d.Outcome)
	}
}

// ── Gate 4 Tests ─────────────────────────────────────────────────────────────

func TestGate4_Pass_BusinessHours(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)
	k := baseKerkese()
	k.TsUTC = time.Date(2026, 4, 5, 10, 0, 0, 0, time.UTC) // 10:00 UTC
	signKerkese(k, opPriv, vfPriv)
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[3].Status != GatePass {
		t.Errorf("gate4: expected PASS during business hours, got %s: %s", d.Gates[3].Status, d.Gates[3].Reason)
	}
}

func TestGate4_Warn_OffHours(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)
	k := baseKerkese()
	k.TsUTC = time.Date(2026, 4, 5, 2, 0, 0, 0, time.UTC) // 02:00 UTC — off-hours
	signKerkese(k, opPriv, vfPriv)
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
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "auditor")
	engine := New(store, verifier)
	k := baseKerkese()
	k.Actor.Role = "operator"
	k.Verifier.Role = "auditor"
	k.Action.Type = "DATA_EXPORT"
	k.Action.IncidentID = "" // missing incident_id → HARD_STOP
	signKerkese(k, opPriv, vfPriv)
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[3].Status != GateHardStop {
		t.Errorf("gate4: expected HARD_STOP for DATA_EXPORT without incident_id, got %s", d.Gates[3].Status)
	}
	if d.Outcome != OutcomeHardStop {
		t.Errorf("expected HARD_STOP outcome, got %s", d.Outcome)
	}
}

func TestGate4_Pass_DataExportWithIncident(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "auditor")
	engine := New(store, verifier)
	k := baseKerkese()
	k.Actor.Role = "operator"
	k.Verifier.Role = "auditor"
	k.Action.Type = "DATA_EXPORT"
	k.Action.IncidentID = "INC-2026-001" // provided → allowed
	signKerkese(k, opPriv, vfPriv)
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Gates[3].Status == GateHardStop {
		t.Errorf("gate4: DATA_EXPORT with incident_id should not HARD_STOP")
	}
}

// ── Gate 5 Tests ─────────────────────────────────────────────────────────────

func TestGate5_AlwaysWritesWORM(t *testing.T) {
	store, verifier, _, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)

	// Even a REFUSE decision must produce a WORM entry
	k := baseKerkese()
	k.Actor.Role = "viewer" // will be refused at gate 2

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
	store, verifier, opPriv, _ := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)
	k := baseKerkese()
	k.SoD.VerifierUserID = k.SoD.OperatorUserID // triggers HARD_STOP at gate 3
	k.Verifier.UserID = k.Actor.UserID
	signKerkese(k, opPriv, opPriv)
	k.VerifierToken = operatorToken
	d, _ := engine.Evaluate(context.Background(), k)
	if d.Outcome != OutcomeHardStop {
		t.Errorf("expected HARD_STOP, got %s", d.Outcome)
	}
	if d.WORMEntryID == nil {
		t.Error("gate5: WORM entry must be written even on HARD_STOP")
	}
}

func TestGate5_PersistsSignatures(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)

	_, _ = engine.Evaluate(context.Background(), k)
	if len(store.wormEntries) != 1 {
		t.Fatalf("expected 1 WORM entry, got %d", len(store.wormEntries))
	}
	got := store.wormEntries[0]
	if got.SigOperator != k.SigOperator || got.SigVerifier != k.SigVerifier {
		t.Errorf("gate5: WORM entry did not persist signatures: got op=%q vf=%q, want op=%q vf=%q",
			got.SigOperator, got.SigVerifier, k.SigOperator, k.SigVerifier)
	}
}

// ── Full Decision Tests ───────────────────────────────────────────────────────

func TestEvaluate_Execute_AllGatesPass(t *testing.T) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier)
	k := baseKerkese()
	signKerkese(k, opPriv, vfPriv)
	d, err := engine.Evaluate(context.Background(), k)
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
	store, verifier := newMockStore(), newMockTokenVerifier() // no tokens → gate1 fails
	engine := New(store, verifier)
	k := baseKerkese()
	k.DryRun = true
	d, _ := engine.Evaluate(context.Background(), k)
	if !d.DryRun {
		t.Error("dry_run flag must be preserved in Decision")
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkMARSHAL_Evaluate(b *testing.B) {
	store, verifier, opPriv, vfPriv := storeWithUsers("operator", "analyst")
	engine := New(store, verifier).EnforceIdentity(true).EnforceSignatures(true)
	k := baseKerkese()
	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.ExecutionID = uuid.New()
		signKerkese(k, opPriv, vfPriv)
		_, _ = engine.Evaluate(ctx, k)
	}
}
