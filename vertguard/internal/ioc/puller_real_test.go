package ioc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/metrics"
)

// memStore is a full pullerStore implementation backed by a map, letting
// Puller.Tick / runSource / runSweep / Run be driven end-to-end without a
// live Postgres connection. Distinct from puller_test.go's fakeStore,
// which only backs the hand-rolled runTick helper.
type memStore struct {
	mu           sync.Mutex
	rows         map[string]IOC
	audits       []PullAudit
	upsertErr    error
	auditErr     error
	sweepErr     error
	countErr     error
	sweepDeleted int64
	activeCount  int64
	sweepCalls   int
	countCalls   int
}

func newMemStore() *memStore {
	return &memStore{rows: map[string]IOC{}}
}

func (m *memStore) key(k Kind, v, t string) string { return string(k) + "|" + v + "|" + t }

func (m *memStore) Upsert(_ context.Context, in IOC) (UpsertResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upsertErr != nil {
		return 0, m.upsertErr
	}
	k := m.key(in.Kind, in.Value, in.Tenant)
	if _, ok := m.rows[k]; ok {
		m.rows[k] = in
		return UpsertUpdated, nil
	}
	m.rows[k] = in
	return UpsertInserted, nil
}

func (m *memStore) AuditInsert(_ context.Context, a PullAudit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.auditErr != nil {
		return m.auditErr
	}
	m.audits = append(m.audits, a)
	return nil
}

func (m *memStore) ExpireSweep(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepCalls++
	if m.sweepErr != nil {
		return 0, m.sweepErr
	}
	return m.sweepDeleted, nil
}

func (m *memStore) CountActive(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countCalls++
	if m.countErr != nil {
		return 0, m.countErr
	}
	return m.activeCount, nil
}

func (m *memStore) rowCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

func (m *memStore) auditCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.audits)
}

func (m *memStore) lastAudit() PullAudit {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.audits[len(m.audits)-1]
}

// fakeSource is a Source with fully scriptable behaviour for driving
// Tick's branches deterministically.
type fakeSource struct {
	name  string
	items []IOC
	err   error
}

func (f fakeSource) Name() string { return f.name }
func (f fakeSource) Fetch(context.Context) ([]IOC, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.items, nil
}

// spyMetrics records every call so tests can assert on pull-result
// bookkeeping without depending on the Prometheus registry.
type spyMetrics struct {
	mu       sync.Mutex
	pulls    map[string]int // "name|result" -> count
	failures map[string]int
	active   float64
}

func newSpyMetrics() *spyMetrics {
	return &spyMetrics{pulls: map[string]int{}, failures: map[string]int{}}
}
func (s *spyMetrics) IncPull(name, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pulls[name+"|"+result]++
}
func (s *spyMetrics) IncFailure(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[name]++
}
func (s *spyMetrics) SetActive(v float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = v
}
func (s *spyMetrics) pullCount(name, result string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pulls[name+"|"+result]
}

// spyCitadel records EmitAsync calls.
type spyCitadel struct {
	mu    sync.Mutex
	evs   []citadel.Evidence
	retOK bool
}

func (c *spyCitadel) EmitAsync(_ context.Context, ev citadel.Evidence) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, ev)
	return c.retOK
}
func (c *spyCitadel) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.evs)
}

var _ metrics.IOCMetrics = (*spyMetrics)(nil)
var _ pullerStore = (*memStore)(nil)

func TestPuller_Tick_HappyPath_InsertsAndAudits(t *testing.T) {
	src := fakeSource{name: "src-a", items: []IOC{
		{Kind: KindIP, Value: "198.51.100.5", Confidence: 0.6},
		{Kind: KindDomain, Value: "evil.example", Confidence: 0.7},
	}}
	store := newMemStore()
	met := newSpyMetrics()
	cit := &spyCitadel{retOK: true}
	p := New(PullerConfig{Store: store, Metrics: met, Citadel: cit, Tenant: "acme", Logger: zerolog.Nop()})

	if err := p.Tick(context.Background(), src); err != nil {
		t.Fatalf("Tick() error = %v", err)
	}
	if store.rowCount() != 2 {
		t.Fatalf("rowCount = %d, want 2", store.rowCount())
	}
	if store.auditCount() != 1 {
		t.Fatalf("auditCount = %d, want 1", store.auditCount())
	}
	a := store.lastAudit()
	if a.Fetched != 2 || a.Inserted != 2 || a.Updated != 0 || a.Skipped != 0 {
		t.Fatalf("audit = %+v, want fetched=2 inserted=2", a)
	}
	if met.pullCount("src-a", "ok") != 1 {
		t.Fatalf("pull ok metric not recorded")
	}
	if cit.count() != 1 {
		t.Fatalf("citadel EmitAsync not called")
	}
	if cit.evs[0].EventType != "vertguard.threatfeed.sync_complete" || cit.evs[0].Subject != "threatfeed/src-a" {
		t.Errorf("citadel evidence = %+v, unexpected fields", cit.evs[0])
	}

	// Second tick with the same value should update, not insert.
	if err := p.Tick(context.Background(), src); err != nil {
		t.Fatalf("second Tick() error = %v", err)
	}
	a2 := store.lastAudit()
	if a2.Updated != 2 || a2.Inserted != 0 {
		t.Fatalf("second audit = %+v, want updated=2 inserted=0", a2)
	}
}

func TestPuller_Tick_TenantDefaultsWhenItemTenantEmpty(t *testing.T) {
	src := fakeSource{name: "src-tenant", items: []IOC{{Kind: KindIP, Value: "203.0.113.9"}}}
	store := newMemStore()
	p := New(PullerConfig{Store: store, Tenant: "tenant-x", Logger: zerolog.Nop()})

	if err := p.Tick(context.Background(), src); err != nil {
		t.Fatalf("Tick() error = %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, row := range store.rows {
		if row.Tenant != "tenant-x" {
			t.Errorf("row.Tenant = %q, want tenant-x (defaulted)", row.Tenant)
		}
	}
}

func TestPuller_Tick_FetchErrorRecordsAuditAndFailureMetric(t *testing.T) {
	src := fakeSource{name: "src-fail", err: errors.New("boom")}
	store := newMemStore()
	met := newSpyMetrics()
	p := New(PullerConfig{Store: store, Metrics: met, Logger: zerolog.Nop()})

	err := p.Tick(context.Background(), src)
	if err == nil {
		t.Fatal("Tick() error = nil, want fetch error propagated")
	}
	if store.auditCount() != 1 {
		t.Fatalf("auditCount = %d, want 1 (audit written even on fetch failure)", store.auditCount())
	}
	a := store.lastAudit()
	if a.Error == "" {
		t.Error("audit.Error empty, want fetch error message recorded")
	}
	if met.failures["src-fail"] != 1 {
		t.Errorf("IncFailure not recorded")
	}
	if met.pullCount("src-fail", "fail") != 1 {
		t.Errorf("pull fail metric not recorded")
	}
}

func TestPuller_Tick_SkipsInvalidKindAndEmptyValue(t *testing.T) {
	src := fakeSource{name: "src-invalid", items: []IOC{
		{Kind: Kind("bogus"), Value: "x"},
		{Kind: KindIP, Value: ""},
		{Kind: KindIP, Value: "203.0.113.20"},
	}}
	store := newMemStore()
	p := New(PullerConfig{Store: store, Logger: zerolog.Nop()})

	if err := p.Tick(context.Background(), src); err != nil {
		t.Fatalf("Tick() error = %v", err)
	}
	a := store.lastAudit()
	if a.Skipped != 2 || a.Inserted != 1 {
		t.Fatalf("audit = %+v, want skipped=2 inserted=1", a)
	}
}

func TestPuller_Tick_AllowlistOverlapSkips(t *testing.T) {
	src := fakeSource{name: "src-allow", items: []IOC{
		{Kind: KindIP, Value: "10.0.0.5"},
		{Kind: KindIP, Value: "203.0.113.30"},
	}}
	store := newMemStore()
	allow := NewAllowlist([]string{"10.0.0.0/8"})
	p := New(PullerConfig{Store: store, Allow: allow, Logger: zerolog.Nop()})

	if err := p.Tick(context.Background(), src); err != nil {
		t.Fatalf("Tick() error = %v", err)
	}
	a := store.lastAudit()
	if a.Skipped != 1 || a.Inserted != 1 {
		t.Fatalf("audit = %+v, want skipped=1 inserted=1", a)
	}
}

func TestPuller_Tick_UpsertErrorSkipsButContinues(t *testing.T) {
	src := fakeSource{name: "src-upserterr", items: []IOC{
		{Kind: KindIP, Value: "203.0.113.40"},
		{Kind: KindIP, Value: "203.0.113.41"},
	}}
	store := newMemStore()
	store.upsertErr = errors.New("db down")
	p := New(PullerConfig{Store: store, Logger: zerolog.Nop()})

	if err := p.Tick(context.Background(), src); err != nil {
		t.Fatalf("Tick() error = %v, want nil (upsert failures are per-item, not fatal)", err)
	}
	a := store.lastAudit()
	if a.Skipped != 2 || a.Inserted != 0 {
		t.Fatalf("audit = %+v, want skipped=2 inserted=0", a)
	}
}

func TestPuller_Tick_AuditInsertErrorDoesNotFailTick(t *testing.T) {
	src := fakeSource{name: "src-auditerr", items: []IOC{{Kind: KindIP, Value: "203.0.113.50"}}}
	store := newMemStore()
	store.auditErr = errors.New("audit write failed")
	p := New(PullerConfig{Store: store, Logger: zerolog.Nop()})

	if err := p.Tick(context.Background(), src); err != nil {
		t.Fatalf("Tick() error = %v, want nil (audit-insert failure is logged, not fatal)", err)
	}
}

func TestPuller_Tick_NoCitadelConfiguredSkipsEmit(t *testing.T) {
	src := fakeSource{name: "src-nocit", items: []IOC{{Kind: KindIP, Value: "203.0.113.60"}}}
	store := newMemStore()
	p := New(PullerConfig{Store: store, Logger: zerolog.Nop()}) // Citadel left nil

	if err := p.Tick(context.Background(), src); err != nil {
		t.Fatalf("Tick() error = %v", err)
	}
	// No panic and no observable side effect — nothing further to assert
	// beyond "didn't blow up", which is the point of emitSync's nil guard.
}

func TestPuller_RunSweep_DeletesAndSetsActiveMetric(t *testing.T) {
	store := newMemStore()
	store.sweepDeleted = 3
	store.activeCount = 7
	met := newSpyMetrics()
	p := New(PullerConfig{
		Store: store, Metrics: met, Logger: zerolog.Nop(),
		SweepInterval: 5 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.runSweep(ctx)
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for {
		store.mu.Lock()
		calls := store.sweepCalls
		store.mu.Unlock()
		if calls >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for runSweep to fire")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	met.mu.Lock()
	active := met.active
	met.mu.Unlock()
	if active != 7 {
		t.Errorf("active metric = %v, want 7", active)
	}
}

func TestPuller_RunSweep_ErrorLogsAndContinues(t *testing.T) {
	store := newMemStore()
	store.sweepErr = errors.New("sweep failed")
	p := New(PullerConfig{
		Store: store, Logger: zerolog.Nop(),
		SweepInterval: 5 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.runSweep(ctx)
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for {
		store.mu.Lock()
		calls := store.sweepCalls
		store.mu.Unlock()
		if calls >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for repeated sweep attempts despite errors")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	// CountActive must never be reached once ExpireSweep errors (continue
	// skips it).
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.countCalls != 0 {
		t.Errorf("countCalls = %d, want 0 (sweep error should short-circuit CountActive)", store.countCalls)
	}
}

func TestPuller_RunSource_FiresImmediatelyThenOnTicker(t *testing.T) {
	store := newMemStore()
	src := fakeSource{name: "src-sched", items: []IOC{{Kind: KindIP, Value: "203.0.113.70"}}}
	p := New(PullerConfig{Store: store, Logger: zerolog.Nop()})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.runSource(ctx, SourceSpec{Source: src, Interval: 10 * time.Millisecond})
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for store.auditCount() < 2 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for at least 2 ticks (immediate + ticker)")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestPuller_RunSource_LogsErrorsAndKeepsRunning(t *testing.T) {
	store := newMemStore()
	src := fakeSource{name: "src-always-fail", err: errors.New("upstream down")}
	p := New(PullerConfig{Store: store, Logger: zerolog.Nop()})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.runSource(ctx, SourceSpec{Source: src, Interval: 5 * time.Millisecond})
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for store.auditCount() < 2 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for repeated failed ticks")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestPuller_Run_WithSourcesAndStore_StopsOnCancel(t *testing.T) {
	store := newMemStore()
	src := fakeSource{name: "src-run", items: []IOC{{Kind: KindIP, Value: "203.0.113.80"}}}
	p := New(PullerConfig{
		Store:         store,
		Sources:       []SourceSpec{{Source: src, Interval: 10 * time.Millisecond}},
		Logger:        zerolog.Nop(),
		SweepInterval: 10 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run() did not return after context cancellation")
	}
	if store.auditCount() == 0 {
		t.Error("expected at least one tick to have run before cancellation")
	}
}

func TestPuller_Run_IdleWhenNoSources(t *testing.T) {
	store := newMemStore()
	p := New(PullerConfig{Store: store, Logger: zerolog.Nop()}) // no Sources

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after context cancellation on the idle path")
	}
	if store.auditCount() != 0 {
		t.Error("idle puller must not run any ticks")
	}
}
