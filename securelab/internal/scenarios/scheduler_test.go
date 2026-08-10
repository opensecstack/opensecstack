// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios_test

import (
	"context"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/opensecstack/securelab/internal/db"
	"github.com/opensecstack/securelab/internal/scenarios"
)

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

// TestScheduler_Schedule_ContextCancelledBeforeSlot verifies that Schedule
// returns promptly with an error when the context is already cancelled, and
// crucially that it does NOT consume a concurrency slot in that case (the
// executor goroutine must never be started, since the executor here has a
// nil pool and would panic if invoked).
func TestScheduler_Schedule_ContextCancelledBeforeSlot(t *testing.T) {
	s, err := scenarios.NewScheduler(1, nil, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	env := &db.Environment{Name: "env-1", TargetURL: "http://127.0.0.1:1"}
	err = s.Schedule(ctx, "run-1", &scenarios.ScenarioSpec{Name: "s"}, env)
	if err == nil {
		t.Fatal("expected error when context is already cancelled")
	}
	if got := s.Available(); got != 1 {
		t.Errorf("Available() after cancelled Schedule = %d, want 1 (slot must not be consumed)", got)
	}
}
