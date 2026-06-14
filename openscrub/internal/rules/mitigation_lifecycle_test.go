package rules

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/dataplane"
)

// fakeMitStore is an in-memory MitigationStore that records every Insert
// so the test can assert the start_packets snapshot is identical across
// the batch.
type fakeMitStore struct {
	mu       sync.Mutex
	rows     []MitigationInsert
	failNext int // when >0, the next N Inserts return an error
}

func (s *fakeMitStore) Insert(_ context.Context, m MitigationInsert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext > 0 {
		s.failNext--
		return errors.New("simulated insert failure")
	}
	s.rows = append(s.rows, m)
	return nil
}
func (s *fakeMitStore) FinalizeForRule(context.Context, uuid.UUID, time.Time, int64, int64) error {
	return nil
}
func (s *fakeMitStore) OpenRuleIDs(context.Context) (map[uuid.UUID]struct{}, error) {
	return map[uuid.UUID]struct{}{}, nil
}

// slowStatsClient wraps a NoopClient and reports a fixed PacketsDropped
// figure after a configurable delay. We use it to prove RecoverActive
// only issues a single Stats RPC for the whole batch — if the lifecycle
// regressed to per-rule Stats calls, the test wall time would explode
// past the 5s assertion.
type slowStatsClient struct {
	*dataplane.NoopClient
	delay  time.Duration
	drops  uint64
	calls  int64
	failAll bool
}

func (c *slowStatsClient) Stats(ctx context.Context) (dataplane.Stats, error) {
	atomic.AddInt64(&c.calls, 1)
	if c.failAll {
		return dataplane.Stats{}, errors.New("stats rpc unavailable")
	}
	select {
	case <-time.After(c.delay):
	case <-ctx.Done():
		return dataplane.Stats{}, ctx.Err()
	}
	return dataplane.Stats{PacketsDropped: c.drops}, nil
}

func TestRecoverActiveSharesStatsSnapshot(t *testing.T) {
	store := &fakeMitStore{}
	plane := &slowStatsClient{
		NoopClient: dataplane.NewNoopClient(),
		delay:      50 * time.Millisecond,
		drops:      42_000,
	}
	lc := NewLifecycle(LifecycleDeps{
		Store:  store,
		Plane:  plane,
		Logger: zerolog.Nop(),
	})

	// 100 active rules.
	active := make([]Rule, 0, 100)
	for i := 0; i < 100; i++ {
		active = append(active, Rule{
			ID: uuid.New(), Type: TypeBlocklist,
			CIDR: "203.0.113.0/24", Source: SourceOperator,
		})
	}

	start := time.Now()
	lc.RecoverActive(context.Background(), active)
	elapsed := time.Since(start)

	// If the lifecycle regressed to a Stats RPC per rule, this would
	// take >= 100 * 50ms = 5s. The single-RPC contract puts it under
	// 1s comfortably even on slow CI.
	if elapsed > 2*time.Second {
		t.Fatalf("RecoverActive took %v — Stats RPC not shared across batch", elapsed)
	}
	if got := atomic.LoadInt64(&plane.calls); got != 1 {
		t.Fatalf("expected exactly 1 Stats call, got %d", got)
	}
	if len(store.rows) != 100 {
		t.Fatalf("expected 100 mitigation rows, got %d", len(store.rows))
	}
	for _, row := range store.rows {
		if row.StartPacketsDropped != 42_000 {
			t.Fatalf("rule %s got start_packets=%d, want 42000",
				row.RuleID, row.StartPacketsDropped)
		}
	}
}

func TestRecoverActiveStatsFailureUsesZeroSnapshot(t *testing.T) {
	store := &fakeMitStore{}
	plane := &slowStatsClient{
		NoopClient: dataplane.NewNoopClient(),
		failAll:    true,
	}
	lc := NewLifecycle(LifecycleDeps{
		Store:  store,
		Plane:  plane,
		Logger: zerolog.Nop(),
	})
	active := []Rule{
		{ID: uuid.New(), Type: TypeBlocklist, CIDR: "203.0.113.0/24"},
		{ID: uuid.New(), Type: TypeBlocklist, CIDR: "198.51.100.0/24"},
	}
	// Must not panic, must still insert rows with a 0 snapshot.
	lc.RecoverActive(context.Background(), active)
	if len(store.rows) != 2 {
		t.Fatalf("expected 2 rows even with Stats failure, got %d", len(store.rows))
	}
	for _, r := range store.rows {
		if r.StartPacketsDropped != 0 {
			t.Fatalf("expected zero snapshot, got %d", r.StartPacketsDropped)
		}
	}
}

func TestRecoverActivePartialInsertFailureContinues(t *testing.T) {
	// First insert fails, the rest must still succeed.
	store := &fakeMitStore{failNext: 1}
	plane := dataplane.NewNoopClient()
	lc := NewLifecycle(LifecycleDeps{
		Store:  store,
		Plane:  plane,
		Logger: zerolog.Nop(),
	})
	active := []Rule{
		{ID: uuid.New(), Type: TypeBlocklist, CIDR: "203.0.113.0/24"},
		{ID: uuid.New(), Type: TypeBlocklist, CIDR: "198.51.100.0/24"},
		{ID: uuid.New(), Type: TypeBlocklist, CIDR: "192.0.2.0/24"},
	}
	lc.RecoverActive(context.Background(), active)
	if len(store.rows) != 2 {
		t.Fatalf("expected 2 rows after 1 transient failure, got %d", len(store.rows))
	}
}

// guard — slowStatsClient must satisfy dataplane.Client.
var _ dataplane.Client = (*slowStatsClient)(nil)

// silence unused-import lint when netip happens not to be referenced
// after future edits; tests intentionally reach into the dataplane
// package for prefix construction in some scenarios.
var _ = netip.Prefix{}
