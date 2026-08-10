package rules

// OnRuleCreated / OnRuleDeleted were previously untested (0%) even
// though the collaborators they call (insertWithSnapshot, readDrops)
// were exercised only via RecoverActive. These tests hit the two
// single-rule entry points directly.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/dataplane"
)

func TestLifecycleOnRuleCreatedInsertsSnapshotRow(t *testing.T) {
	store := &fakeMitStore{}
	plane := &slowStatsClient{NoopClient: dataplane.NewNoopClient(), drops: 777}
	lc := NewLifecycle(LifecycleDeps{Store: store, Plane: plane, Logger: zerolog.Nop()})

	r := Rule{ID: uuid.New(), Type: TypeBlocklist, CIDR: "203.0.113.0/24", Source: SourceOperator}
	lc.OnRuleCreated(context.Background(), r)

	if len(store.rows) != 1 {
		t.Fatalf("expected 1 mitigation row, got %d", len(store.rows))
	}
	got := store.rows[0]
	if got.RuleID != r.ID {
		t.Fatalf("RuleID = %s, want %s", got.RuleID, r.ID)
	}
	if got.RuleCIDR != r.CIDR || got.RuleType != string(r.Type) || got.RuleSource != r.Source {
		t.Fatalf("row does not mirror rule: %+v", got)
	}
	if got.StartPacketsDropped != 777 {
		t.Fatalf("StartPacketsDropped = %d, want 777 (from Stats snapshot)", got.StartPacketsDropped)
	}
	if got.ID == uuid.Nil {
		t.Fatal("expected a generated mitigation row id")
	}
}

// TestLifecycleOnRuleCreatedNilStoreIsSafeNoOp proves the documented
// dev-mode contract: a Lifecycle built with no store must never panic
// and must never call the dataplane (which may also be nil).
func TestLifecycleOnRuleCreatedNilStoreIsSafeNoOp(t *testing.T) {
	lc := NewLifecycle(LifecycleDeps{Logger: zerolog.Nop()})
	lc.OnRuleCreated(context.Background(), Rule{ID: uuid.New()})
	// No assertion beyond "did not panic" — store is nil so the method
	// must return immediately per the guard clause.
}

// TestLifecycleOnRuleCreatedNilReceiverIsSafe proves the `l == nil`
// guard: Service callers hold a MitigationLifecycle interface, and a
// typed-nil *Lifecycle stored in that interface is non-nil as an
// interface value — the explicit l == nil check inside the method
// prevents a nil-pointer dereference in that case.
func TestLifecycleOnRuleCreatedNilReceiverIsSafe(t *testing.T) {
	var lc *Lifecycle
	lc.OnRuleCreated(context.Background(), Rule{ID: uuid.New()})
	lc.OnRuleDeleted(context.Background(), Rule{ID: uuid.New()})
	lc.RecoverActive(context.Background(), []Rule{{ID: uuid.New()}})
}

func TestLifecycleOnRuleDeletedFinalizesRow(t *testing.T) {
	store := &finalizeRecordingStore{}
	fixedNow := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	lc := NewLifecycle(LifecycleDeps{
		Store: store, Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop(),
		Now: func() time.Time { return fixedNow },
	})

	r := Rule{ID: uuid.New(), Type: TypeBlocklist, CIDR: "198.51.100.0/24"}
	lc.OnRuleDeleted(context.Background(), r)

	if store.calls != 1 {
		t.Fatalf("expected 1 FinalizeForRule call, got %d", store.calls)
	}
	if store.lastRuleID != r.ID {
		t.Fatalf("FinalizeForRule ruleID = %s, want %s", store.lastRuleID, r.ID)
	}
	if !store.lastEndedAt.Equal(fixedNow) {
		t.Fatalf("FinalizeForRule endedAt = %v, want %v", store.lastEndedAt, fixedNow)
	}
}

// TestLifecycleOnRuleDeletedFinalizeErrorDoesNotPanic proves the
// best-effort contract documented on OnRuleDeleted: a store error is
// logged, not surfaced or panicked on (the method has no return
// value at all).
func TestLifecycleOnRuleDeletedFinalizeErrorDoesNotPanic(t *testing.T) {
	store := &finalizeRecordingStore{err: errors.New("db unavailable")}
	lc := NewLifecycle(LifecycleDeps{Store: store, Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop()})
	lc.OnRuleDeleted(context.Background(), Rule{ID: uuid.New()})
	if store.calls != 1 {
		t.Fatalf("expected FinalizeForRule to still be attempted once, got %d calls", store.calls)
	}
}

// TestLifecycleOnRuleDeletedNilStoreIsSafeNoOp mirrors the Create-side
// dev-mode guard for the delete path.
func TestLifecycleOnRuleDeletedNilStoreIsSafeNoOp(t *testing.T) {
	lc := NewLifecycle(LifecycleDeps{Logger: zerolog.Nop()})
	lc.OnRuleDeleted(context.Background(), Rule{ID: uuid.New()})
}

// finalizeRecordingStore is a minimal MitigationStore stub focused on
// FinalizeForRule's arguments (fakeMitStore in
// mitigation_lifecycle_test.go always returns nil there without
// recording call details).
type finalizeRecordingStore struct {
	calls       int
	lastRuleID  uuid.UUID
	lastEndedAt time.Time
	err         error
}

func (s *finalizeRecordingStore) Insert(context.Context, MitigationInsert) error { return nil }
func (s *finalizeRecordingStore) FinalizeForRule(_ context.Context, ruleID uuid.UUID, endedAt time.Time, _, _ int64) error {
	s.calls++
	s.lastRuleID = ruleID
	s.lastEndedAt = endedAt
	return s.err
}
func (s *finalizeRecordingStore) OpenRuleIDs(context.Context) (map[uuid.UUID]struct{}, error) {
	return map[uuid.UUID]struct{}{}, nil
}
