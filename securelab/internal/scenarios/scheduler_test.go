// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/opensecstack/securelab/internal/db"
	"github.com/opensecstack/securelab/internal/scenarios"
)

// Note: Schedule's success path spawns a goroutine that invokes the
// configured *Executor, which in turn requires a *pgxpool.Pool. Rather than
// requiring a live SECURELAB_DB_URL database (see executor_test.go's
// testPool skip-gated helper), TestScheduler_Schedule_AcquiresAndReleasesSlot
// below uses unreachablePool (also from executor_test.go) so Execute fails
// fast on its first DB call instead of blocking indefinitely — this still
// exercises Schedule's real slot acquisition/release around a genuine
// Executor, deterministically and without Docker/Postgres.
//
// We deliberately do not construct a Scheduler with a nil *Executor: that
// would require racing a pre-cancelled context against
// `select { case s.sem <- struct{}{}: ... case <-ctx.Done(): ... }`, which
// has no defined precedence between a ready send and an already-cancelled
// context and would non-deterministically spawn a goroutine that panics
// against a nil executor. The context-cancelled branch is instead covered
// deterministically below by cancelling ctx while the single concurrency
// slot is legitimately held (so the send case is genuinely not ready).

func TestNewScheduler_RejectsNonPositiveConcurrency(t *testing.T) {
	for _, n := range []int{0, -1, -5} {
		if _, err := scenarios.NewScheduler(n, nil, zaptest.NewLogger(t)); err == nil {
			t.Errorf("NewScheduler(%d, ...) expected error, got nil", n)
		}
	}
}

func TestNewScheduler_ValidConcurrency(t *testing.T) {
	s, err := scenarios.NewScheduler(3, nil, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := s.Available(); got != 3 {
		t.Errorf("Available() = %d, want 3", got)
	}
}

func TestNewScheduler_AvailableMatchesCapacityForVariousLimits(t *testing.T) {
	for _, n := range []int{1, 5, 100} {
		s, err := scenarios.NewScheduler(n, nil, zaptest.NewLogger(t))
		if err != nil {
			t.Fatalf("unexpected error for maxConcurrent=%d: %v", n, err)
		}
		if got := s.Available(); got != n {
			t.Errorf("Available() for maxConcurrent=%d = %d, want %d", n, got, n)
		}
	}
}

// TestScheduler_Schedule_AcquiresAndReleasesSlot exercises Schedule's
// success path end-to-end: a slot is acquired synchronously, the run
// executes in the background (failing fast because the DB is unreachable),
// and the slot is released once the background Execute call returns. It
// also covers Schedule's context-cancelled branch deterministically by
// issuing a second Schedule call with an already-cancelled context while the
// single slot is still legitimately held.
func TestScheduler_Schedule_AcquiresAndReleasesSlot(t *testing.T) {
	pool := unreachablePool(t)

	disp := &mockDispatcher{success: true}
	mon := &mockMonitor{}
	log := zaptest.NewLogger(t)
	exec := scenarios.NewExecutor(pool, disp, mon, log)

	sched, err := scenarios.NewScheduler(1, exec, log)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	env := &db.Environment{Name: "sched-test", TargetURL: "http://192.168.99.99:8080"}
	spec := oneStepSpec()

	if err := sched.Schedule(context.Background(), "sched-run-1", spec, env); err != nil {
		t.Fatalf("Schedule returned error: %v", err)
	}

	// The single slot must be taken immediately after a successful Schedule
	// call, before the background run has had any chance to finish.
	if got := sched.Available(); got != 0 {
		t.Fatalf("Available() immediately after Schedule = %d, want 0", got)
	}

	// With the only slot held, a second Schedule call given an
	// already-cancelled context must return ctx.Err() rather than blocking:
	// the semaphore send is genuinely not ready, so only the ctx.Done() case
	// can fire — no race with the slot-acquired branch.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sched.Schedule(cancelledCtx, "sched-run-2", spec, env); err == nil {
		t.Error("expected an error scheduling against a cancelled context with no free slot")
	}

	// Wait for the background Execute call (which fails fast against the
	// unreachable DB) to release the slot.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && sched.Available() != 1 {
		time.Sleep(50 * time.Millisecond)
	}
	if got := sched.Available(); got != 1 {
		t.Errorf("Available() after background run completion = %d, want 1 (slot not released)", got)
	}
}
