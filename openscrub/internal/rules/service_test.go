package rules

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/citadel"
	"github.com/opensecstack/openscrub/internal/dataplane"
)

type fakeEmitter struct {
	events []any
}

func (f *fakeEmitter) Submit(_ context.Context, ev any) (citadel.SubmitOutcome, error) {
	f.events = append(f.events, ev)
	return citadel.SubmitDelivered, nil
}

// fakeLifecycle records OnRuleCreated / OnRuleDeleted invocations so
// tests can assert that the service drives the mitigation evidence
// path on every lifecycle transition (BLOCKER 1 regression guard).
type fakeLifecycle struct {
	mu        sync.Mutex
	created   []Rule
	deleted   []Rule
	recovered [][]Rule
}

func (f *fakeLifecycle) OnRuleCreated(_ context.Context, r Rule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, r)
}
func (f *fakeLifecycle) OnRuleDeleted(_ context.Context, r Rule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, r)
}
func (f *fakeLifecycle) RecoverActive(_ context.Context, rs []Rule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recovered = append(f.recovered, rs)
}

// waitFor polls fn until it returns true or the deadline elapses.
// The lifecycle hooks are now invoked in goroutines (so a slow Stats
// RPC does not block the HTTP handler), so tests must wait for the
// callback to land before asserting.
func waitFor(t *testing.T, timeout time.Duration, msg string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

func newSvc(t *testing.T) (*Service, *dataplane.NoopClient, *fakeEmitter, *fakeLifecycle) {
	t.Helper()
	plane := dataplane.NewNoopClient()
	em := &fakeEmitter{}
	lc := &fakeLifecycle{}
	return New(Deps{
		Repo: NewMemoryRepo(), Plane: plane, Emitter: em, Lifecycle: lc,
		NodeName: "test-node", Logger: zerolog.Nop(),
	}), plane, em, lc
}

func TestServiceCreateBlocklistInstallsAndEmits(t *testing.T) {
	svc, plane, em, lc := newSvc(t)
	r, err := svc.Create(context.Background(), CreateRequest{
		Type: TypeBlocklist, CIDR: "203.0.113.0/24", TTLSeconds: 3600, Source: SourceOperator,
	}, "operator-juni", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == uuid.Nil {
		t.Fatal("rule id zero")
	}
	snap, _ := plane.Snapshot(context.Background())
	if len(snap.BlocklistV4) != 1 || snap.BlocklistV4[0].String() != "203.0.113.0/24" {
		t.Fatalf("blocklist not installed: %+v", snap)
	}
	if len(em.events) != 1 {
		t.Fatalf("expected 1 emitted event, got %d", len(em.events))
	}
	ev, ok := em.events[0].(citadel.RuleChangeEvent)
	if !ok {
		t.Fatalf("unexpected event type %T", em.events[0])
	}
	if ev.Operation != citadel.OpInsert || ev.Principal != "operator-juni" {
		t.Fatalf("unexpected event %+v", ev)
	}
	// BLOCKER 1 regression: a successful Create MUST open a mitigation
	// evidence window. Otherwise the watcher's PendingForEmit returns
	// nothing and CITADEL never sees `openscrub.mitigation`. The hook
	// fires in a goroutine so the HTTP handler isn't gated on the
	// dataplane Stats RPC — wait for the callback to land.
	waitFor(t, time.Second, "OnRuleCreated to fire", func() bool {
		lc.mu.Lock()
		defer lc.mu.Unlock()
		return len(lc.created) == 1 && lc.created[0].ID == r.ID
	})
}

func TestServiceCreateThreatFlowEmitsIOCApply(t *testing.T) {
	svc, _, em, _ := newSvc(t)
	_, err := svc.Create(context.Background(), CreateRequest{
		Type: TypeBlocklist, CIDR: "198.51.100.7/32",
		TTLSeconds: 86400, Source: SourceThreatFlow,
	}, "threatflow-puller", nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := em.events[0].(citadel.RuleChangeEvent)
	if ev.Operation != citadel.OpIOCPullApply {
		t.Fatalf("expected ioc_pull_apply, got %s", ev.Operation)
	}
}

func TestServiceDeleteRemovesAndEmits(t *testing.T) {
	svc, plane, em, lc := newSvc(t)
	r, _ := svc.Create(context.Background(), CreateRequest{
		Type: TypeBlocklist, CIDR: "10.0.0.0/8", TTLSeconds: 60,
	}, "op", nil)
	em.events = nil

	if err := svc.Delete(context.Background(), r.ID, "op", "manual"); err != nil {
		t.Fatal(err)
	}
	snap, _ := plane.Snapshot(context.Background())
	if len(snap.BlocklistV4) != 0 {
		t.Fatalf("blocklist not cleared: %+v", snap)
	}
	if len(em.events) != 1 || em.events[0].(citadel.RuleChangeEvent).Operation != citadel.OpWithdraw {
		t.Fatalf("expected one withdraw event, got %+v", em.events)
	}
	// BLOCKER 1 regression: a successful Delete MUST finalize the
	// mitigation evidence window so the watcher emits the event. Same
	// async caveat as the Create case above.
	waitFor(t, time.Second, "OnRuleDeleted to fire", func() bool {
		lc.mu.Lock()
		defer lc.mu.Unlock()
		return len(lc.deleted) == 1 && lc.deleted[0].ID == r.ID
	})
}

func TestServiceDeleteUnknownReturnsErrNotFound(t *testing.T) {
	svc, _, _, _ := newSvc(t)
	err := svc.Delete(context.Background(), uuid.New(), "op", "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestServiceSweepExpiredEmitsExpire(t *testing.T) {
	plane := dataplane.NewNoopClient()
	em := &fakeEmitter{}
	now := time.Now().UTC()
	clock := now
	svc := New(Deps{
		Repo: NewMemoryRepo(), Plane: plane, Emitter: em,
		NodeName: "n", Logger: zerolog.Nop(),
		Now: func() time.Time { return clock },
	})
	if _, err := svc.Create(context.Background(), CreateRequest{
		Type: TypeBlocklist, CIDR: "192.0.2.0/24", TTLSeconds: 1,
	}, "op", nil); err != nil {
		t.Fatal(err)
	}
	em.events = nil

	clock = now.Add(2 * time.Second)
	n, err := svc.SweepExpired(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("sweep n=%d err=%v", n, err)
	}
	if len(em.events) != 1 || em.events[0].(citadel.RuleChangeEvent).Operation != citadel.OpExpire {
		t.Fatalf("expected expire event, got %+v", em.events)
	}
	snap, _ := plane.Snapshot(context.Background())
	if len(snap.BlocklistV4) != 0 {
		t.Fatalf("expired rule still in plane")
	}
}

func TestServiceCreateSynCookieInstallsAndEmits(t *testing.T) {
	svc, plane, em, _ := newSvc(t)
	port := 443
	r, err := svc.Create(context.Background(), CreateRequest{
		Type: TypeSynCookie, Port: &port, TTLSeconds: 600, Source: SourceOperator,
	}, "operator-juni", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Port == nil || *r.Port != 443 {
		t.Fatalf("port not stored: %+v", r)
	}
	snap, _ := plane.Snapshot(context.Background())
	if len(snap.SynCookiePorts) != 1 || snap.SynCookiePorts[0] != 443 {
		t.Fatalf("syncookie port not installed: %+v", snap)
	}
	if len(em.events) != 1 {
		t.Fatalf("expected 1 emitted event, got %d", len(em.events))
	}

	if err := svc.Delete(context.Background(), r.ID, "op", ""); err != nil {
		t.Fatal(err)
	}
	snap, _ = plane.Snapshot(context.Background())
	if len(snap.SynCookiePorts) != 0 {
		t.Fatalf("syncookie port not cleared: %+v", snap)
	}
}

// TestServiceListPagination is the regression guard for the
// `offset+limit` blocker: the OpenAPI contract advertises offset
// pagination but earlier revisions silently dropped it, so every page
// returned the first N rows. With 5 rules and limit=2, walking
// offset=0,2,4 must visit each rule exactly once with no overlap.
func TestServiceListPagination(t *testing.T) {
	svc, _, _, _ := newSvc(t)
	ctx := context.Background()
	// Insert 5 rules — distinct CIDRs to make the assertion readable.
	cidrs := []string{
		"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32",
		"203.0.113.4/32", "203.0.113.5/32",
	}
	for _, c := range cidrs {
		if _, err := svc.Create(ctx, CreateRequest{
			Type: TypeBlocklist, CIDR: c, TTLSeconds: 60,
		}, "op", nil); err != nil {
			t.Fatalf("create %s: %v", c, err)
		}
		// Force distinct created_at so the order is deterministic even
		// without the id-DESC tiebreaker (the tiebreaker is exercised
		// in the integration test against real Postgres).
		time.Sleep(time.Millisecond)
	}

	page0, err := svc.List(ctx, "", 2, 0)
	if err != nil || len(page0) != 2 {
		t.Fatalf("page0: len=%d err=%v", len(page0), err)
	}
	page1, err := svc.List(ctx, "", 2, 2)
	if err != nil || len(page1) != 2 {
		t.Fatalf("page1: len=%d err=%v", len(page1), err)
	}
	page2, err := svc.List(ctx, "", 2, 4)
	if err != nil || len(page2) != 1 {
		t.Fatalf("page2: len=%d err=%v", len(page2), err)
	}
	// No overlap between pages.
	seen := map[uuid.UUID]struct{}{}
	for _, p := range [][]Rule{page0, page1, page2} {
		for _, r := range p {
			if _, dup := seen[r.ID]; dup {
				t.Fatalf("duplicate rule across pages: %s", r.ID)
			}
			seen[r.ID] = struct{}{}
		}
	}
	if len(seen) != 5 {
		t.Fatalf("expected 5 distinct rules across pages, got %d", len(seen))
	}
	// offset past end returns empty, not error.
	pageEmpty, err := svc.List(ctx, "", 2, 100)
	if err != nil || len(pageEmpty) != 0 {
		t.Fatalf("offset past end: len=%d err=%v", len(pageEmpty), err)
	}
}

func TestServiceCreateRatelimitInstallsRatelimit(t *testing.T) {
	svc, plane, _, _ := newSvc(t)
	pps := 500
	_, err := svc.Create(context.Background(), CreateRequest{
		Type: TypeRatelimit, CIDR: "198.51.100.5/32", PPS: &pps, TTLSeconds: 60,
	}, "op", nil)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := plane.Snapshot(context.Background())
	if len(snap.Ratelimits) != 1 {
		t.Fatalf("ratelimit not installed: %+v", snap)
	}
}
