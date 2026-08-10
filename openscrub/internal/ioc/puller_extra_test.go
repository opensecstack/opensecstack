package ioc

// Covers Run() (previously 0%) and isAlreadyIngested (previously 0%),
// plus Tick's dedup-skip branch when logFn reports the bundle was
// already ingested.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/rules"
)

func TestIsAlreadyIngested(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("boom"), false},
		{errors.New("bundle already ingested"), true},
		{errors.New("sha256 abc123 already ingested for source threatflow"), true},
	}
	for _, tc := range cases {
		if got := isAlreadyIngested(tc.err); got != tc.want {
			t.Errorf("isAlreadyIngested(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// TestPullerRunNoOpsWhenBaseURLEmpty proves Run() returns immediately
// (rather than starting a ticker against an empty target) when no
// ThreatFlow URL is configured — the documented "disabled" state.
func TestPullerRunNoOpsWhenBaseURLEmpty(t *testing.T) {
	svc := rules.New(rules.Deps{
		Repo: rules.NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop(),
	})
	puller := New(Config{BaseURL: ""}, svc, zerolog.Nop(), nil)

	done := make(chan struct{})
	go func() {
		puller.Run(context.Background()) // must return promptly, not block forever
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return promptly with an empty BaseURL")
	}
}

// TestPullerRunTicksUntilContextCancelled proves Run() fires an
// immediate tick, then continues ticking on the configured interval,
// and stops cleanly when ctx is cancelled.
func TestPullerRunTicksUntilContextCancelled(t *testing.T) {
	var tickCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&tickCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	svc := rules.New(rules.Deps{
		Repo: rules.NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop(),
	})
	puller := New(Config{BaseURL: srv.URL, Interval: 20 * time.Millisecond}, svc, zerolog.Nop(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		puller.Run(ctx)
		close(done)
	}()

	// Immediate tick + at least one interval tick.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt64(&tickCount) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&tickCount); got < 2 {
		t.Fatalf("expected at least 2 ticks (immediate + interval), got %d", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after context cancellation")
	}
}

// TestPullerTickSkipsApplyWhenAlreadyIngested proves the dedup branch:
// when logFn reports the bundle's hash was already ingested, Tick
// must return nil without attempting to apply any IOCs as rules.
func TestPullerTickSkipsApplyWhenAlreadyIngested(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"type":"ip","value":"198.51.100.7"}]}`))
	}))
	defer srv.Close()

	plane := dataplane.NewNoopClient()
	svc := rules.New(rules.Deps{
		Repo: rules.NewMemoryRepo(), Plane: plane, Logger: zerolog.Nop(),
	})
	puller := New(Config{BaseURL: srv.URL, Interval: time.Hour, RuleTTL: time.Hour}, svc, zerolog.Nop(),
		func(context.Context, string, string, int) error {
			return errors.New("bundle already ingested")
		})

	if err := puller.Tick(context.Background()); err != nil {
		t.Fatalf("expected nil error on dedup skip, got %v", err)
	}
	snap, _ := plane.Snapshot(context.Background())
	if len(snap.BlocklistV4) != 0 {
		t.Fatalf("expected no rules applied on dedup skip, got %+v", snap.BlocklistV4)
	}
}

// TestPullerTickLogFnHardErrorPropagates proves a non-dedup logFn
// error is wrapped and returned (distinct from the dedup branch
// above), so Tick's caller (Run) sees and logs the real failure.
func TestPullerTickLogFnHardErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()

	svc := rules.New(rules.Deps{
		Repo: rules.NewMemoryRepo(), Plane: dataplane.NewNoopClient(), Logger: zerolog.Nop(),
	})
	puller := New(Config{BaseURL: srv.URL}, svc, zerolog.Nop(),
		func(context.Context, string, string, int) error {
			return errors.New("db connection refused")
		})

	err := puller.Tick(context.Background())
	if err == nil {
		t.Fatal("expected error to propagate from logFn")
	}
}
