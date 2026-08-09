package permifysync

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func testLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}

// fakeFetcher is a MatrixFetcher test double: each call pops the next
// scripted (matrix, err) result off calls, so a test can script exactly
// what a sequence of syncs should see (e.g. success, then failure, then
// success again).
type fakeFetcher struct {
	mu      sync.Mutex
	results []fetchResult
	calls   int32
}

type fetchResult struct {
	matrix map[RoleAction]bool
	err    error
}

func (f *fakeFetcher) FetchRoleActionMatrix(ctx context.Context) (map[RoleAction]bool, error) {
	atomic.AddInt32(&f.calls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.results) == 0 {
		return map[RoleAction]bool{}, nil
	}
	r := f.results[0]
	if len(f.results) > 1 {
		f.results = f.results[1:]
	}
	return r.matrix, r.err
}

func (f *fakeFetcher) callCount() int {
	return int(atomic.LoadInt32(&f.calls))
}

// fakeStore is an in-memory SnapshotStore test double.
type fakeStore struct {
	mu           sync.Mutex
	data         map[RoleAction]bool
	failReplace  bool
	replaceCalls int
}

func newFakeStore() *fakeStore {
	return &fakeStore{data: make(map[RoleAction]bool)}
}

func (s *fakeStore) ReplaceSnapshot(ctx context.Context, rows map[RoleAction]bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replaceCalls++
	if s.failReplace {
		return errors.New("fake store: replace failed")
	}
	cp := make(map[RoleAction]bool, len(rows))
	for k, v := range rows {
		cp[k] = v
	}
	s.data = cp
	return nil
}

func (s *fakeStore) LoadSnapshot(ctx context.Context) (map[RoleAction]bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(map[RoleAction]bool, len(s.data))
	for k, v := range s.data {
		cp[k] = v
	}
	return cp, nil
}

func (s *fakeStore) snapshot() map[RoleAction]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(map[RoleAction]bool, len(s.data))
	for k, v := range s.data {
		cp[k] = v
	}
	return cp
}

// --- Snapshot.Allowed ---

func TestSnapshot_Allowed_UnknownByDefault(t *testing.T) {
	snap := NewSnapshot()

	allowed, known := snap.Allowed("admin", "API_SCAN_INITIATE")
	if known {
		t.Fatalf("expected known=false for an empty snapshot, got known=true (allowed=%v)", allowed)
	}
	if allowed {
		t.Fatalf("expected allowed=false (zero value) when known=false")
	}
}

func TestSnapshot_Allowed_KnownAfterReplace(t *testing.T) {
	snap := NewSnapshot()
	snap.replace(map[RoleAction]bool{
		{Role: "admin", ActionType: "API_SCAN_INITIATE"}: true,
		{Role: "viewer", ActionType: "DATA_EXPORT"}:      false,
	})

	if allowed, known := snap.Allowed("admin", "API_SCAN_INITIATE"); !known || !allowed {
		t.Fatalf("expected known=true, allowed=true; got known=%v allowed=%v", known, allowed)
	}
	if allowed, known := snap.Allowed("viewer", "DATA_EXPORT"); !known || allowed {
		t.Fatalf("expected known=true, allowed=false; got known=%v allowed=%v", known, allowed)
	}
	if _, known := snap.Allowed("analyst", "IOC_INGEST"); known {
		t.Fatalf("expected known=false for a pair never synced")
	}
}

func TestSnapshot_Replace_NilDataProducesEmptyNotNilPanic(t *testing.T) {
	snap := NewSnapshot()
	snap.replace(nil)
	if _, known := snap.Allowed("admin", "X"); known {
		t.Fatalf("expected known=false after replacing with nil")
	}
	if snap.Len() != 0 {
		t.Fatalf("expected Len()=0, got %d", snap.Len())
	}
}

// --- Syncer.refreshOnce / Run ---

func TestSyncer_SuccessfulFetch_UpdatesSnapshotAndStore(t *testing.T) {
	fetcher := &fakeFetcher{results: []fetchResult{
		{matrix: map[RoleAction]bool{{Role: "admin", ActionType: "API_SCAN_INITIATE"}: true}},
	}}
	store := newFakeStore()
	snap := NewSnapshot()
	s := New(fetcher, store, snap, time.Hour, testLogger())

	s.refreshOnce(context.Background())

	if allowed, known := snap.Allowed("admin", "API_SCAN_INITIATE"); !known || !allowed {
		t.Fatalf("expected snapshot updated: known=true allowed=true, got known=%v allowed=%v", known, allowed)
	}
	if got := store.snapshot(); len(got) != 1 {
		t.Fatalf("expected store to have 1 row, got %d", len(got))
	}
}

func TestSyncer_FetchFailure_KeepsExistingSnapshotAndStore(t *testing.T) {
	fetcher := &fakeFetcher{results: []fetchResult{
		{matrix: map[RoleAction]bool{{Role: "admin", ActionType: "API_SCAN_INITIATE"}: true}},
		{err: errors.New("permify unreachable")},
	}}
	store := newFakeStore()
	snap := NewSnapshot()
	s := New(fetcher, store, snap, time.Hour, testLogger())

	// First refresh succeeds and populates data.
	s.refreshOnce(context.Background())
	if got := store.snapshot(); len(got) != 1 {
		t.Fatalf("setup: expected 1 row after first successful refresh, got %d", len(got))
	}

	// Second refresh fails — must not clear/alter the existing data.
	s.refreshOnce(context.Background())

	if allowed, known := snap.Allowed("admin", "API_SCAN_INITIATE"); !known || !allowed {
		t.Fatalf("expected prior snapshot data to survive a fetch failure, got known=%v allowed=%v", known, allowed)
	}
	if got := store.snapshot(); len(got) != 1 {
		t.Fatalf("expected store to still have 1 row after fetch failure, got %d", len(got))
	}
	// Store.ReplaceSnapshot must not have been called a second time.
	if store.replaceCalls != 1 {
		t.Fatalf("expected exactly 1 store replace call (failure short-circuits before the store), got %d", store.replaceCalls)
	}
}

func TestSyncer_StoreFailure_KeepsExistingInMemorySnapshot(t *testing.T) {
	fetcher := &fakeFetcher{results: []fetchResult{
		{matrix: map[RoleAction]bool{{Role: "admin", ActionType: "API_SCAN_INITIATE"}: true}},
	}}
	store := newFakeStore()
	snap := NewSnapshot()
	s := New(fetcher, store, snap, time.Hour, testLogger())
	s.refreshOnce(context.Background()) // seed a known-good state
	store.failReplace = true

	fetcher.results = []fetchResult{{matrix: map[RoleAction]bool{{Role: "viewer", ActionType: "DATA_EXPORT"}: true}}}
	s.refreshOnce(context.Background())

	// In-memory snapshot must still reflect the last successful state, not
	// the fetched-but-not-persisted one.
	if allowed, known := snap.Allowed("admin", "API_SCAN_INITIATE"); !known || !allowed {
		t.Fatalf("expected in-memory snapshot to keep prior state when the store write fails")
	}
	if _, known := snap.Allowed("viewer", "DATA_EXPORT"); known {
		t.Fatalf("expected the fetched-but-not-persisted row to NOT be visible in-memory")
	}
}

func TestSyncer_EmptyButSuccessfulFetch_ReplacesWithEmpty(t *testing.T) {
	// A successful fetch that legitimately finds nothing (today's real
	// state, per PermifyFetcher's doc comment) must still replace prior
	// data — this is different from a failure, which must NOT replace.
	fetcher := &fakeFetcher{results: []fetchResult{
		{matrix: map[RoleAction]bool{{Role: "admin", ActionType: "API_SCAN_INITIATE"}: true}},
		{matrix: map[RoleAction]bool{}},
	}}
	store := newFakeStore()
	snap := NewSnapshot()
	s := New(fetcher, store, snap, time.Hour, testLogger())

	s.refreshOnce(context.Background())
	s.refreshOnce(context.Background())

	if _, known := snap.Allowed("admin", "API_SCAN_INITIATE"); known {
		t.Fatalf("expected a successful-but-empty fetch to clear prior data")
	}
	if got := store.snapshot(); len(got) != 0 {
		t.Fatalf("expected store to be empty after a successful-but-empty fetch, got %d rows", len(got))
	}
}

func TestSyncer_Run_TicksUntilContextCanceled(t *testing.T) {
	fetcher := &fakeFetcher{}
	store := newFakeStore()
	snap := NewSnapshot()
	s := New(fetcher, store, snap, 10*time.Millisecond, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// Run performs an immediate refresh on start, then ticks every 10ms;
	// give it enough time to accumulate several calls.
	time.Sleep(80 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	if calls := fetcher.callCount(); calls < 2 {
		t.Fatalf("expected at least 2 fetch calls (immediate + at least one tick), got %d", calls)
	}
}

// TestSyncer_Snapshot_ReturnsSameInstancePassedToNew confirms Snapshot() is
// a plain accessor returning the exact *Snapshot instance the caller
// constructed and shared via New — not a copy — since callers (server.go's
// registerRoutes) rely on this to hand the same live, concurrently-updated
// snapshot to Gate 2.
func TestSyncer_Snapshot_ReturnsSameInstancePassedToNew(t *testing.T) {
	snap := NewSnapshot()
	s := New(&fakeFetcher{}, newFakeStore(), snap, time.Hour, testLogger())

	got := s.Snapshot()
	if got != snap {
		t.Fatal("expected Snapshot() to return the exact same *Snapshot instance passed to New")
	}

	// Mutating through the returned accessor must be visible on the
	// original reference, proving it is the same object, not a copy.
	got.replace(map[RoleAction]bool{{Role: "admin", ActionType: "X"}: true})
	if allowed, known := snap.Allowed("admin", "X"); !known || !allowed {
		t.Fatal("expected mutation through Snapshot() to be visible on the original *Snapshot")
	}
}

func TestSyncer_LoadInitial_PopulatesSnapshotFromStore(t *testing.T) {
	store := newFakeStore()
	store.data[RoleAction{Role: "admin", ActionType: "API_SCAN_INITIATE"}] = true

	snap := NewSnapshot()
	s := New(&fakeFetcher{}, store, snap, time.Hour, testLogger())

	if err := s.LoadInitial(context.Background()); err != nil {
		t.Fatalf("LoadInitial: unexpected error: %v", err)
	}

	if allowed, known := snap.Allowed("admin", "API_SCAN_INITIATE"); !known || !allowed {
		t.Fatalf("expected LoadInitial to populate the in-memory snapshot from the store")
	}
}
