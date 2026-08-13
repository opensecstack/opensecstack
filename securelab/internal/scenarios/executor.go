// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/opensecstack/securelab/internal/db"
)

// AttackEvent records the outcome of a single attack step execution.
type AttackEvent struct {
	StepIndex int            `json:"step_index"`
	Kind      string         `json:"kind"`
	Params    map[string]any `json:"params,omitempty"`
	StartedAt time.Time      `json:"started_at"`
	Duration  string         `json:"duration_ms"`
	Success   bool           `json:"success"`
	Error     string         `json:"error,omitempty"`
}

// DetectionEvent records a detection signal received from a monitored platform.
type DetectionEvent struct {
	Platform   string    `json:"platform"`
	AlertID    string    `json:"alert_id,omitempty"`
	ReceivedAt time.Time `json:"received_at"`
	Latency    int64     `json:"latency_ms"`
	Payload    any       `json:"payload,omitempty"`
}

// AttackDispatcher is the interface that each attack-kind implementation must
// satisfy. Dispatch executes the step against the given target URL and returns
// whether the attack succeeded, plus any error.
type AttackDispatcher interface {
	Dispatch(ctx context.Context, step StepSpec, targetURL string) (success bool, err error)
}

// DetectionMonitor waits for an alert from monitored platforms after an attack
// is dispatched. WaitForDetection blocks until an alert is received, the
// context is cancelled, or the timeout is exceeded.
type DetectionMonitor interface {
	WaitForDetection(ctx context.Context) (*DetectionEvent, error)
}

// citadelEmitter is the subset of citadel.Connector used by the executor.
type citadelEmitter interface {
	EmitRunCompleted(ctx context.Context, runID, scenarioName, status string, detectionRate float64) error
}

// Executor orchestrates the execution of a scenario run: it iterates over
// each step, dispatches attacks, collects detection events, and persists the
// final run status to the database.
type Executor struct {
	pool       *pgxpool.Pool
	dispatcher AttackDispatcher
	monitor    DetectionMonitor
	log        *zap.Logger
	citadel    citadelEmitter
}

// NewExecutor constructs an Executor with the required dependencies.
func NewExecutor(pool *pgxpool.Pool, dispatcher AttackDispatcher, monitor DetectionMonitor, log *zap.Logger) *Executor {
	return &Executor{
		pool:       pool,
		dispatcher: dispatcher,
		monitor:    monitor,
		log:        log,
	}
}

// WithCitadel attaches a CITADEL emitter. When set, a securelab.run_completed
// event is posted after every run completes. Non-fatal: emit errors are logged.
func (e *Executor) WithCitadel(c citadelEmitter) {
	e.citadel = c
}

// Execute runs every step in spec against env, recording attack and detection
// events. It updates the scenario_runs row identified by runID with the final
// status and collected telemetry.
func (e *Executor) Execute(ctx context.Context, runID string, spec *ScenarioSpec, env *db.Environment) error {
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	now := time.Now().UTC()
	run := &db.ScenarioRun{
		ID:     runID,
		Status: "running",
		StartedAt: &now,
	}
	if err := db.UpdateRunStatus(execCtx, e.pool, run); err != nil {
		return fmt.Errorf("executor: mark running: %w", err)
	}

	attackEvents, finalStatus, notes := e.runSteps(execCtx, runID, spec, env)

	// After all attack steps, wait for a detection signal.
	detected := false
	var detectionLatencyMs *int
	detectionEvents := make([]DetectionEvent, 0)
	if finalStatus != "error" {
		detected, detectionEvents, detectionLatencyMs = e.waitForDetection(execCtx, runID)
	}

	attackJSON, err := json.Marshal(attackEvents)
	if err != nil {
		attackJSON = []byte("[]")
	}
	detectionJSON, err := json.Marshal(detectionEvents)
	if err != nil {
		detectionJSON = []byte("[]")
	}

	finishedAt := time.Now().UTC()
	finalRun := &db.ScenarioRun{
		ID:                 runID,
		Status:             finalStatus,
		StartedAt:          &now,
		FinishedAt:         &finishedAt,
		AttackEvents:       json.RawMessage(attackJSON),
		DetectionEvents:    json.RawMessage(detectionJSON),
		DetectionLatencyMs: detectionLatencyMs,
		Detected:           &detected,
		Notes:              notes,
	}

	if updateErr := db.UpdateRunStatus(ctx, e.pool, finalRun); updateErr != nil {
		return fmt.Errorf("executor: persist final status: %w", updateErr)
	}

	e.log.Info("scenario run complete",
		zap.String("run_id", runID),
		zap.String("status", finalStatus),
		zap.Bool("detected", detected),
	)

	if e.citadel != nil {
		rate := 0.0
		if detected {
			rate = 1.0
		}
		citCtx, citCancel := context.WithTimeout(ctx, 5*time.Second)
		defer citCancel()
		if emitErr := e.citadel.EmitRunCompleted(citCtx, runID, spec.Name, finalStatus, rate); emitErr != nil {
			e.log.Warn("citadel emit failed", zap.Error(emitErr))
		}
	}

	return nil
}

// runSteps dispatches every step in spec.Steps against env in order,
// recording an AttackEvent per step. It stops early — without dispatching
// remaining steps — if ctx is cancelled or times out between steps, in which
// case it returns status "error" and an explanatory note. Otherwise it
// returns status "failed" if any step's dispatch returned an error, or
// "passed" if every step dispatched without error. runSteps performs no
// database or network I/O of its own beyond e.dispatcher.Dispatch and
// e.log, so it is safe to unit test without a live database.
func (e *Executor) runSteps(ctx context.Context, runID string, spec *ScenarioSpec, env *db.Environment) (events []AttackEvent, status string, notes string) {
	events = make([]AttackEvent, 0, len(spec.Steps))
	status = "passed"

	for i, step := range spec.Steps {
		if ctx.Err() != nil {
			status = "error"
			notes = "context cancelled or timed out during step execution"
			break
		}

		stepStart := time.Now().UTC()
		e.log.Info("dispatching attack step",
			zap.String("run_id", runID),
			zap.Int("step_index", i),
			zap.String("kind", step.Kind),
			zap.String("target", env.TargetURL),
		)

		success, dispatchErr := e.dispatcher.Dispatch(ctx, step, env.TargetURL)
		elapsed := time.Since(stepStart)

		ev := AttackEvent{
			StepIndex: i,
			Kind:      step.Kind,
			Params:    step.Params,
			StartedAt: stepStart,
			Duration:  fmt.Sprintf("%d", elapsed.Milliseconds()),
			Success:   success,
		}
		if dispatchErr != nil {
			ev.Error = dispatchErr.Error()
			status = "failed"
			e.log.Warn("attack step failed",
				zap.String("run_id", runID),
				zap.Int("step_index", i),
				zap.Error(dispatchErr),
			)
		}
		events = append(events, ev)
	}
	return events, status, notes
}

// waitForDetection blocks — bounded by a 30-second sub-timeout derived from
// ctx — until a detection signal arrives from e.monitor, ctx is cancelled,
// or the sub-timeout expires. It returns whether a detection was observed,
// the (possibly empty) list of DetectionEvents, and the detection latency in
// milliseconds when one was observed (nil otherwise). Like runSteps, it does
// no database I/O and is safe to unit test independently of Execute.
func (e *Executor) waitForDetection(ctx context.Context, runID string) (detected bool, events []DetectionEvent, latencyMs *int) {
	events = make([]DetectionEvent, 0)

	detCtx, detCancel := context.WithTimeout(ctx, 30*time.Second)
	defer detCancel()
	detEv, detErr := e.monitor.WaitForDetection(detCtx)

	if detErr == nil && detEv != nil {
		lat := int(detEv.Latency)
		latencyMs = &lat
		events = append(events, *detEv)
		e.log.Info("detection confirmed",
			zap.String("run_id", runID),
			zap.String("platform", detEv.Platform),
			zap.Int64("latency_ms", detEv.Latency),
		)
	} else if detErr != nil {
		e.log.Warn("no detection received",
			zap.String("run_id", runID),
			zap.Error(detErr),
		)
	}
	return latencyMs != nil, events, latencyMs
}
