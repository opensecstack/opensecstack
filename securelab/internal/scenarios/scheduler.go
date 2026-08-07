// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/opensecstack/securelab/internal/db"
)

// Scheduler enforces a cap on the number of concurrently executing scenario
// runs. It uses a buffered channel as a semaphore so that Schedule is
// non-blocking up to the configured concurrency limit, after which callers
// block until a slot becomes free or their context is cancelled.
type Scheduler struct {
	sem      chan struct{}
	executor *Executor
	log      *zap.Logger
}

// NewScheduler constructs a Scheduler that permits at most maxConcurrent
// simultaneous runs.
func NewScheduler(maxConcurrent int, executor *Executor, log *zap.Logger) (*Scheduler, error) {
	if maxConcurrent <= 0 {
		return nil, fmt.Errorf("scheduler: maxConcurrent must be > 0, got %d", maxConcurrent)
	}
	return &Scheduler{
		sem:      make(chan struct{}, maxConcurrent),
		executor: executor,
		log:      log,
	}, nil
}

// Schedule acquires a concurrency slot and then executes the scenario run in a
// new goroutine. If the context is cancelled while waiting for a slot, it
// returns ctx.Err() without starting the run. The concurrency slot is
// released automatically when the run finishes.
//
// The caller should have already inserted the run row with status=pending
// before calling Schedule; the executor will transition it to running/passed/
// failed/error.
func (s *Scheduler) Schedule(ctx context.Context, runID string, spec *ScenarioSpec, env *db.Environment) error {
	// Block until a slot is available or the context is done.
	select {
	case s.sem <- struct{}{}:
		// Slot acquired.
	case <-ctx.Done():
		return fmt.Errorf("scheduler: context cancelled while waiting for slot: %w", ctx.Err())
	}

	s.log.Info("scenario run scheduled",
		zap.String("run_id", runID),
		zap.String("scenario", spec.Name),
		zap.String("environment", env.Name),
		zap.Int("queue_depth", len(s.sem)),
	)

	go func() {
		defer func() { <-s.sem }()

		if err := s.executor.Execute(ctx, runID, spec, env); err != nil {
			s.log.Error("scenario run executor error",
				zap.String("run_id", runID),
				zap.Error(err),
			)
		}
	}()

	return nil
}

// Available returns the number of free concurrency slots at the moment of
// the call.
func (s *Scheduler) Available() int {
	return cap(s.sem) - len(s.sem)
}
