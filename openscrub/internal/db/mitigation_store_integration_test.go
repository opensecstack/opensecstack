// Integration test against a real Postgres instance. Skipped unless
// OPENSCRUB_TEST_DB_URL is set (see rule_store_integration_test.go for
// the full convention).

package db_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/opensecstack/openscrub/internal/db"
	"github.com/opensecstack/openscrub/internal/rules"
)

// insertTestRule is a small helper that inserts a blocklist rule and
// returns its id, for tests that need a real rule to hang mitigation
// rows off.
func insertTestRule(t *testing.T, ctx context.Context, ruleStore *db.RuleStore, cidr string) uuid.UUID {
	t.Helper()
	r, err := ruleStore.Insert(ctx, rules.Rule{
		Type: rules.TypeBlocklist, CIDR: cidr,
		TTLSeconds: 3600, Source: rules.SourceOperator,
	})
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	return r.ID
}

func TestMitigationStoreInsertGetClose(t *testing.T) {
	pool := openTestDB(t)
	ctx := context.Background()
	ruleStore := db.NewRuleStore(pool)
	store := db.NewMitigationStore(pool)

	ruleID := insertTestRule(t, ctx, ruleStore, "198.51.100.0/24")
	src := netip.MustParseAddr("203.0.113.7")

	m := db.Mitigation{
		RuleID:     uuid.NullUUID{UUID: ruleID, Valid: true},
		RuleCIDR:   "198.51.100.0/24",
		RuleType:   string(rules.TypeBlocklist),
		RuleSource: string(rules.SourceOperator),
		SrcIP:      &src,
	}
	inserted, err := store.Insert(ctx, m)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if inserted.ID == uuid.Nil {
		t.Fatal("expected generated id")
	}
	if inserted.State != "pending" {
		t.Fatalf("expected default state pending, got %q", inserted.State)
	}

	got, err := store.Get(ctx, inserted.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.RuleID.Valid || got.RuleID.UUID != ruleID {
		t.Fatalf("unexpected rule id: %+v", got.RuleID)
	}
	if got.RuleCIDR != "198.51.100.0/24" || got.RuleType != string(rules.TypeBlocklist) {
		t.Fatalf("unexpected snapshot: %+v", got)
	}
	if got.SrcIP == nil || *got.SrcIP != src {
		t.Fatalf("unexpected src ip: %+v", got.SrcIP)
	}
	if got.EndedAt != nil {
		t.Fatalf("expected open mitigation, got EndedAt=%v", got.EndedAt)
	}

	endedAt := time.Now().UTC()
	if err := store.Close(ctx, inserted.ID, endedAt, 1000, 50000); err != nil {
		t.Fatalf("close: %v", err)
	}

	closed, err := store.Get(ctx, inserted.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed.EndedAt == nil {
		t.Fatal("expected EndedAt to be set after Close")
	}
	if closed.PacketsDropped != 1000 || closed.BytesDropped != 50000 {
		t.Fatalf("unexpected counters after close: %+v", closed)
	}
}

func TestMitigationStoreGetNotFound(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewMitigationStore(pool)

	_, err := store.Get(context.Background(), uuid.New())
	if !errors.Is(err, db.ErrMitigationNotFound) {
		t.Fatalf("expected ErrMitigationNotFound, got %v", err)
	}
}

func TestMitigationStoreFinalizeForRule(t *testing.T) {
	pool := openTestDB(t)
	ctx := context.Background()
	ruleStore := db.NewRuleStore(pool)
	store := db.NewMitigationStore(pool)

	ruleID := insertTestRule(t, ctx, ruleStore, "203.0.113.0/24")

	inserted, err := store.Insert(ctx, db.Mitigation{
		RuleID:              uuid.NullUUID{UUID: ruleID, Valid: true},
		RuleCIDR:            "203.0.113.0/24",
		RuleType:            string(rules.TypeBlocklist),
		RuleSource:          string(rules.SourceOperator),
		StartPacketsDropped: 1000,
		StartBytesDropped:   50000,
	})
	if err != nil {
		t.Fatal(err)
	}

	endedAt := time.Now().UTC()
	// end < start on bytes: FinalizeForRule must clamp the negative
	// delta to zero rather than writing a nonsense negative window
	// (covers a counter-rollover scenario after a loader restart).
	if err := store.FinalizeForRule(ctx, ruleID, endedAt, 1500, 40000); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	got, err := store.Get(ctx, inserted.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EndedAt == nil {
		t.Fatal("expected EndedAt to be set")
	}
	if got.PacketsDropped != 500 {
		t.Fatalf("expected packets_dropped=500 (1500-1000), got %d", got.PacketsDropped)
	}
	if got.BytesDropped != 0 {
		t.Fatalf("expected bytes_dropped clamped to 0, got %d", got.BytesDropped)
	}

	// Idempotent: no open row left, so a second call is a no-op and
	// must not error or touch the already-closed row again.
	if err := store.FinalizeForRule(ctx, ruleID, endedAt.Add(time.Minute), 9999, 9999); err != nil {
		t.Fatalf("second finalize: %v", err)
	}
	got2, err := store.Get(ctx, inserted.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got2.PacketsDropped != 500 {
		t.Fatalf("expected finalize to be idempotent, got %+v", got2)
	}
}

func TestMitigationStoreOpenRuleIDs(t *testing.T) {
	pool := openTestDB(t)
	ctx := context.Background()
	ruleStore := db.NewRuleStore(pool)
	store := db.NewMitigationStore(pool)

	openRule := insertTestRule(t, ctx, ruleStore, "192.0.2.0/24")
	closedRule := insertTestRule(t, ctx, ruleStore, "192.0.2.128/25")

	if _, err := store.Insert(ctx, db.Mitigation{
		RuleID: uuid.NullUUID{UUID: openRule, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	closedMit, err := store.Insert(ctx, db.Mitigation{
		RuleID: uuid.NullUUID{UUID: closedRule, Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(ctx, closedMit.ID, time.Now().UTC(), 1, 1); err != nil {
		t.Fatal(err)
	}

	open, err := store.OpenRuleIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := open[openRule]; !ok {
		t.Fatalf("expected %s in open set: %v", openRule, open)
	}
	if _, ok := open[closedRule]; ok {
		t.Fatalf("did not expect closed rule %s in open set: %v", closedRule, open)
	}
}

func TestMitigationStoreStateMachine(t *testing.T) {
	pool := openTestDB(t)
	ctx := context.Background()
	store := db.NewMitigationStore(pool)

	inserted, err := store.Insert(ctx, db.Mitigation{})
	if err != nil {
		t.Fatal(err)
	}

	// MarkSending records an in-flight envelope id and bumps attempts.
	if err := store.MarkSending(ctx, inserted.ID, "evt-123"); err != nil {
		t.Fatalf("mark sending: %v", err)
	}
	got, err := store.Get(ctx, inserted.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Attempts != 1 || got.LastError != "in_flight:evt-123" {
		t.Fatalf("unexpected post-MarkSending row: %+v", got)
	}

	// LookupByEventID must resolve the envelope id back to this row.
	foundID, err := store.LookupByEventID(ctx, "evt-123")
	if err != nil {
		t.Fatal(err)
	}
	if foundID != inserted.ID {
		t.Fatalf("expected %s, got %s", inserted.ID, foundID)
	}

	// Unknown event id resolves to uuid.Nil, not an error.
	notFound, err := store.LookupByEventID(ctx, "evt-does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	if notFound != uuid.Nil {
		t.Fatalf("expected uuid.Nil for unknown event id, got %s", notFound)
	}

	// Empty event id short-circuits to uuid.Nil without hitting the DB.
	empty, err := store.LookupByEventID(ctx, "")
	if err != nil || empty != uuid.Nil {
		t.Fatalf("expected (uuid.Nil, nil) for empty event id, got (%s, %v)", empty, err)
	}

	// MarkSent flips state to sent, clears last_error, sets sent_at,
	// and the legacy MarkEmitted alias routes to the same place.
	if err := store.MarkSent(ctx, inserted.ID); err != nil {
		t.Fatalf("mark sent: %v", err)
	}
	got, err = store.Get(ctx, inserted.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "sent" || !got.Emitted || got.LastError != "" || got.SentAt == nil {
		t.Fatalf("unexpected post-MarkSent row: %+v", got)
	}

	// MarkFailed on a second row records a terminal error.
	inserted2, err := store.Insert(ctx, db.Mitigation{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkFailed(ctx, inserted2.ID, "citadel returned 503"); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	got2, err := store.Get(ctx, inserted2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got2.State != "failed" || got2.LastError != "citadel returned 503" {
		t.Fatalf("unexpected post-MarkFailed row: %+v", got2)
	}

	// MarkEmitted (legacy alias) on a third row must behave exactly
	// like MarkSent.
	inserted3, err := store.Insert(ctx, db.Mitigation{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkEmitted(ctx, inserted3.ID); err != nil {
		t.Fatalf("mark emitted: %v", err)
	}
	got3, err := store.Get(ctx, inserted3.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got3.State != "sent" || !got3.Emitted {
		t.Fatalf("expected MarkEmitted to behave like MarkSent, got %+v", got3)
	}

	failedCount, err := store.FailedCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if failedCount != 1 {
		t.Fatalf("expected 1 failed mitigation, got %d", failedCount)
	}
}

func TestMitigationStorePendingForEmit(t *testing.T) {
	pool := openTestDB(t)
	ctx := context.Background()
	store := db.NewMitigationStore(pool)

	now := time.Now().UTC()

	// Eligible: pending, ended, long enough duration, not in flight.
	eligible, err := store.Insert(ctx, db.Mitigation{StartedAt: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(ctx, eligible.ID, now, 10, 10); err != nil {
		t.Fatal(err)
	}

	// Too short: ended almost immediately, below minDuration.
	tooShort, err := store.Insert(ctx, db.Mitigation{StartedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(ctx, tooShort.ID, now.Add(time.Millisecond), 1, 1); err != nil {
		t.Fatal(err)
	}

	// Already sent: must not be returned even though it's ended.
	sent, err := store.Insert(ctx, db.Mitigation{StartedAt: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(ctx, sent.ID, now, 10, 10); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkSent(ctx, sent.ID); err != nil {
		t.Fatal(err)
	}

	// In flight: must be excluded even though pending + ended + long
	// enough, because a live watcher already owns it.
	inFlight, err := store.Insert(ctx, db.Mitigation{StartedAt: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(ctx, inFlight.ID, now, 10, 10); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkSending(ctx, inFlight.ID, "evt-in-flight"); err != nil {
		t.Fatal(err)
	}

	pending, err := store.PendingForEmit(ctx, 30*time.Second, 100)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[uuid.UUID]bool{}
	for _, p := range pending {
		ids[p.ID] = true
	}
	if !ids[eligible.ID] {
		t.Fatalf("expected eligible row %s in pending set", eligible.ID)
	}
	if ids[tooShort.ID] {
		t.Fatal("did not expect too-short row in pending set")
	}
	if ids[sent.ID] {
		t.Fatal("did not expect already-sent row in pending set")
	}
	if ids[inFlight.ID] {
		t.Fatal("did not expect in-flight row in pending set")
	}

	// limit<=0 and limit>500 both clamp to the documented default (100).
	clampedLow, err := store.PendingForEmit(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(clampedLow) == 0 {
		t.Fatal("expected clamp-to-default limit to still return rows")
	}
	if _, err := store.PendingForEmit(ctx, 0, 1000); err != nil {
		t.Fatal(err)
	}
}

func TestMitigationStoreListFilters(t *testing.T) {
	pool := openTestDB(t)
	ctx := context.Background()
	ruleStore := db.NewRuleStore(pool)
	store := db.NewMitigationStore(pool)

	ruleA := insertTestRule(t, ctx, ruleStore, "198.18.0.0/24")
	ruleB := insertTestRule(t, ctx, ruleStore, "198.18.1.0/24")

	older := time.Now().UTC().Add(-2 * time.Hour)
	newer := time.Now().UTC().Add(-time.Minute)

	mA, err := store.Insert(ctx, db.Mitigation{RuleID: uuid.NullUUID{UUID: ruleA, Valid: true}, StartedAt: older})
	if err != nil {
		t.Fatal(err)
	}
	mB, err := store.Insert(ctx, db.Mitigation{RuleID: uuid.NullUUID{UUID: ruleB, Valid: true}, StartedAt: newer})
	if err != nil {
		t.Fatal(err)
	}

	// No filters: both rows come back, newest first.
	all, err := store.List(ctx, time.Time{}, uuid.Nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 2 {
		t.Fatalf("expected at least 2 rows, got %d", len(all))
	}
	if all[0].ID != mB.ID {
		t.Fatalf("expected newest row first, got %+v", all[0])
	}

	// Filter by ruleID: only that rule's row.
	byRule, err := store.List(ctx, time.Time{}, ruleA, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(byRule) != 1 || byRule[0].ID != mA.ID {
		t.Fatalf("expected only ruleA's row, got %+v", byRule)
	}

	// Filter by since: excludes the older row.
	bySince, err := store.List(ctx, time.Now().UTC().Add(-time.Hour), uuid.Nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range bySince {
		if m.ID == mA.ID {
			t.Fatalf("expected older row excluded by since filter: %+v", bySince)
		}
	}

	// limit<=0 and limit>1000 both clamp rather than error.
	if _, err := store.List(ctx, time.Time{}, uuid.Nil, -5); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(ctx, time.Time{}, uuid.Nil, 5000); err != nil {
		t.Fatal(err)
	}
}
