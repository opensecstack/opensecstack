// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios_test

import (
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/opensecstack/securelab/internal/scenarios"
)

// Note: Schedule's success path always spawns a goroutine that invokes the
// configured *Executor, which in turn requires a live DB pool (see
// executor_test.go's testPool skip-without-SECURELAB_DB_URL pattern). We
// deliberately do not exercise Schedule() itself here with a nil executor:
// its internal `select { case s.sem <- struct{}{}: ... case <-ctx.Done():
// ... }` has no defined precedence between a ready send and an
// already-cancelled context, so a test that pre-cancels ctx before calling
// Schedule cannot deterministically avoid the slot-acquired branch — which
// would spawn a goroutine that panics against a nil executor. Only the
// side-effect-free parts of the Scheduler API are covered here.

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
