package main

// Pure-function unit tests for the wiring/adapter logic in main.go.
//
// main() itself, the background-worker goroutines, and the
// *db.MitigationStore-backed adapter methods (PendingForEmit, List,
// Insert, MarkEmitted, ...) all require either a live process
// lifecycle or a live Postgres connection (see internal/db package
// doc comment — those integration tests skip without
// OPENSCRUB_TEST_DB_URL) and are out of scope here.
//
// What *is* pure, in-process testable logic — and where real bugs
// hide — is the field-mapping between the DB row shape and the wire
// shapes each adapter method builds. This file extracts that mapping
// into standalone functions (mitigationRecordFromRow,
// mitigationViewFromRow, mitigationRowFromInsert) and exercises them
// directly, plus the two remaining pure helpers in main.go
// (buildDataplane, runSweeper).

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/citadel"
	"github.com/opensecstack/openscrub/internal/config"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/db"
	"github.com/opensecstack/openscrub/internal/rules"
)

func testLogger() zerolog.Logger {
	return zerolog.New(nil)
}

// --- mitigationRecordFromRow -------------------------------------------------

func TestMitigationRecordFromRowUsesSnapshotWhenPresent(t *testing.T) {
	ruleID := uuid.New()
	src := netip.MustParseAddr("203.0.113.7")
	ended := time.Now().UTC()
	m := db.Mitigation{
		ID:             uuid.New(),
		RuleID:         uuid.NullUUID{UUID: ruleID, Valid: true},
		RuleCIDR:       "203.0.113.0/24",
		RuleType:       "blocklist",
		RuleSource:     "operator",
		StartedAt:      ended.Add(-time.Minute),
		EndedAt:        &ended,
		PacketsDropped: 100,
		BytesDropped:   2000,
		SrcIP:          &src,
	}
	// repo is never consulted when the snapshot is populated; passing
	// nil proves that (a nil-deref would fail the test).
	rec := mitigationRecordFromRow(context.Background(), nil, m)

	if rec.RuleID != ruleID {
		t.Errorf("RuleID = %v, want %v", rec.RuleID, ruleID)
	}
	if rec.EndedAt != ended {
		t.Errorf("EndedAt = %v, want %v", rec.EndedAt, ended)
	}
	if rec.SrcIP != "203.0.113.7" {
		t.Errorf("SrcIP = %q, want 203.0.113.7", rec.SrcIP)
	}
	want := citadel.RuleSummary{ID: ruleID.String(), CIDR: "203.0.113.0/24", Type: "blocklist", Source: "operator"}
	if rec.Rule != want {
		t.Errorf("Rule = %+v, want %+v", rec.Rule, want)
	}
}

func TestMitigationRecordFromRowLegacyFallsBackToRuleLookup(t *testing.T) {
	repo := rules.NewMemoryRepo()
	ctx := context.Background()
	port := 443
	inserted, err := repo.Insert(ctx, rules.Rule{
		Type:       rules.TypeSynCookie,
		Port:       &port,
		TTLSeconds: 60,
		Source:     rules.SourceOperator,
	})
	if err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	// Legacy row: no RuleCIDR/RuleType snapshot, only a RuleID — the
	// pre-0002 shape. The mapper must resolve the live rule.
	m := db.Mitigation{
		ID:     uuid.New(),
		RuleID: uuid.NullUUID{UUID: inserted.ID, Valid: true},
	}
	rec := mitigationRecordFromRow(ctx, repo, m)

	if rec.Rule.ID != inserted.ID.String() {
		t.Errorf("Rule.ID = %q, want %q", rec.Rule.ID, inserted.ID.String())
	}
	if rec.Rule.Type != string(rules.TypeSynCookie) {
		t.Errorf("Rule.Type = %q, want %q", rec.Rule.Type, rules.TypeSynCookie)
	}
	if rec.Rule.TTLSeconds != 60 {
		t.Errorf("Rule.TTLSeconds = %d, want 60", rec.Rule.TTLSeconds)
	}
}

func TestMitigationRecordFromRowLegacyRuleGoneMarksUnknown(t *testing.T) {
	repo := rules.NewMemoryRepo()
	ctx := context.Background()
	danglingID := uuid.New()

	m := db.Mitigation{
		ID:     uuid.New(),
		RuleID: uuid.NullUUID{UUID: danglingID, Valid: true},
	}
	rec := mitigationRecordFromRow(ctx, repo, m)

	if rec.Rule.Type != "unknown" {
		t.Errorf("Rule.Type = %q, want unknown", rec.Rule.Type)
	}
	if rec.Rule.ID != danglingID.String() {
		t.Errorf("Rule.ID = %q, want %q", rec.Rule.ID, danglingID.String())
	}
}

func TestMitigationRecordFromRowNoRuleIDMarksUnknown(t *testing.T) {
	m := db.Mitigation{ID: uuid.New()}
	rec := mitigationRecordFromRow(context.Background(), rules.NewMemoryRepo(), m)

	if rec.Rule.Type != "unknown" || rec.Rule.ID != "" {
		t.Errorf("Rule = %+v, want zero-ID unknown", rec.Rule)
	}
}

// --- mitigationViewFromRow ---------------------------------------------------

func TestMitigationViewFromRowMapsFields(t *testing.T) {
	ruleID := uuid.New()
	src := netip.MustParseAddr("198.51.100.1")
	m := db.Mitigation{
		ID:             uuid.New(),
		RuleID:         uuid.NullUUID{UUID: ruleID, Valid: true},
		StartedAt:      time.Now().UTC(),
		PacketsDropped: 5,
		BytesDropped:   500,
		SrcIP:          &src,
		Emitted:        true,
	}
	v := mitigationViewFromRow(m)

	if v.RuleID != ruleID {
		t.Errorf("RuleID = %v, want %v", v.RuleID, ruleID)
	}
	if v.SrcIP != "198.51.100.1" {
		t.Errorf("SrcIP = %q, want 198.51.100.1", v.SrcIP)
	}
	if !v.Emitted {
		t.Error("Emitted = false, want true")
	}
}

func TestMitigationViewFromRowZeroRuleIDWhenInvalid(t *testing.T) {
	m := db.Mitigation{ID: uuid.New()}
	v := mitigationViewFromRow(m)
	if v.RuleID != uuid.Nil {
		t.Errorf("RuleID = %v, want Nil", v.RuleID)
	}
}

// --- mitigationRowFromInsert --------------------------------------------------

func TestMitigationRowFromInsertMapsFields(t *testing.T) {
	ruleID := uuid.New()
	src := netip.MustParseAddr("192.0.2.1")
	started := time.Now().UTC()
	ins := rules.MitigationInsert{
		ID:                  uuid.New(),
		RuleID:              ruleID,
		RuleCIDR:            "192.0.2.0/24",
		RuleType:            "blocklist",
		RuleSource:          "threatflow",
		StartedAt:           started,
		StartPacketsDropped: 10,
		StartBytesDropped:   1000,
		SrcIP:               &src,
	}
	row := mitigationRowFromInsert(ins)

	if row.RuleID != (uuid.NullUUID{UUID: ruleID, Valid: true}) {
		t.Errorf("RuleID = %+v, want valid %v", row.RuleID, ruleID)
	}
	if row.RuleCIDR != "192.0.2.0/24" || row.RuleSource != "threatflow" {
		t.Errorf("row = %+v", row)
	}
	if row.StartPacketsDropped != 10 || row.StartBytesDropped != 1000 {
		t.Errorf("start counters not preserved: %+v", row)
	}
}

func TestMitigationRowFromInsertNilRuleIDIsInvalid(t *testing.T) {
	row := mitigationRowFromInsert(rules.MitigationInsert{ID: uuid.New()})
	if row.RuleID.Valid {
		t.Errorf("RuleID.Valid = true for uuid.Nil, want false")
	}
}

// --- buildDataplane -----------------------------------------------------------

func TestBuildDataplaneUDS(t *testing.T) {
	cfg := config.Config{DataplaneTransport: "uds", DataplaneSocket: "/tmp/does-not-need-to-exist.sock"}
	client := buildDataplane(cfg, testLogger())
	if _, ok := client.(*dataplane.UDSClient); !ok {
		t.Fatalf("buildDataplane(uds) = %T, want *dataplane.UDSClient", client)
	}
	_ = client.Close()
}

func TestBuildDataplaneDefaultsToNoop(t *testing.T) {
	cfg := config.Config{DataplaneTransport: "bogus"}
	client := buildDataplane(cfg, testLogger())
	if _, ok := client.(*dataplane.NoopClient); !ok {
		t.Fatalf("buildDataplane(bogus) = %T, want *dataplane.NoopClient", client)
	}
	_ = client.Close()
}

// --- runSweeper -----------------------------------------------------------

// stubEmitter satisfies rules.CitadelEmitter without touching CITADEL.
type stubEmitter struct{}

func (stubEmitter) Submit(_ context.Context, _ any) (citadel.SubmitOutcome, error) {
	return citadel.SubmitDelivered, nil
}

func TestRunSweeperExitsOnContextCancel(t *testing.T) {
	repo := rules.NewMemoryRepo()
	svc := rules.New(rules.Deps{
		Repo:    repo,
		Plane:   dataplane.NewNoopClient(),
		Emitter: stubEmitter{},
		Logger:  testLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runSweeper(ctx, svc, time.Hour, testLogger())
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runSweeper did not return after context cancellation")
	}
}

func TestRunSweeperSweepsExpiredRulesOnTick(t *testing.T) {
	repo := rules.NewMemoryRepo()
	ctx := context.Background()
	past := time.Now().UTC().Add(-time.Hour)
	svc := rules.New(rules.Deps{
		Repo:    repo,
		Plane:   dataplane.NewNoopClient(),
		Emitter: stubEmitter{},
		Logger:  testLogger(),
		Now:     func() time.Time { return past.Add(2 * time.Hour) },
	})
	if _, err := repo.Insert(ctx, rules.Rule{
		Type:       rules.TypeBlocklist,
		CIDR:       "203.0.113.0/24",
		TTLSeconds: 1, // already expired relative to svc.now
		Source:     rules.SourceOperator,
		CreatedAt:  past,
	}); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		runSweeper(runCtx, svc, 10*time.Millisecond, testLogger())
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		remaining, err := repo.List(ctx, "", 10, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(remaining) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runSweeper did not return after context cancellation")
	}

	remaining, err := repo.List(ctx, "", 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected expired rule to be swept, got %d remaining", len(remaining))
	}
}
