// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios

// White-box tests for the DB-free portions of Executor: runSteps and
// waitForDetection. Execute itself is exercised end-to-end (with a real
// database) by executor_test.go in package scenarios_test, which is
// skipped without SECURELAB_DB_URL. runSteps and waitForDetection contain
// the bulk of Execute's business logic — dispatch iteration, early-abort on
// context cancellation, and detection-signal handling — and do no I/O of
// their own beyond the injected AttackDispatcher/DetectionMonitor, so they
// can be fully unit tested here without a live database.

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/opensecstack/securelab/internal/db"
)

// fakeDispatcher lets each test script a sequence of per-step outcomes, or
// fall back to a fixed (success, err) pair for every call.
type fakeDispatcher struct {
	sequence []dispatchResult
	calls    []StepSpec
}

type dispatchResult struct {
	success bool
	err     error
}

func (f *fakeDispatcher) Dispatch(_ context.Context, step StepSpec, _ string) (bool, error) {
	f.calls = append(f.calls, step)
	idx := len(f.calls) - 1
	if idx < len(f.sequence) {
		r := f.sequence[idx]
		return r.success, r.err
	}
	return true, nil
}

// blockingDispatcher never returns until its context is cancelled, letting
// tests exercise the mid-loop context-cancellation branch of runSteps.
type blockingDispatcher struct{}

func (blockingDispatcher) Dispatch(ctx context.Context, _ StepSpec, _ string) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

// fakeMonitor returns a scripted (event, err) pair, or blocks until its
// context is done when both are nil.
type fakeMonitor struct {
	event *DetectionEvent
	err   error
}

func (f *fakeMonitor) WaitForDetection(ctx context.Context) (*DetectionEvent, error) {
	if f.event != nil || f.err != nil {
		return f.event, f.err
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func specWithSteps(steps ...StepSpec) *ScenarioSpec {
	return &ScenarioSpec{Name: "internal-test", Severity: "low", Steps: steps}
}

// ---------------------------------------------------------------------------
// runSteps
// ---------------------------------------------------------------------------

func TestRunSteps_AllSucceed(t *testing.T) {
	disp := &fakeDispatcher{sequence: []dispatchResult{{success: true}, {success: true}}}
	e := &Executor{dispatcher: disp, log: zaptest.NewLogger(t)}
	spec := specWithSteps(StepSpec{Kind: "bola"}, StepSpec{Kind: "ssrf"})
	env := &db.Environment{TargetURL: "http://target.example"}

	events, status, notes := e.runSteps(context.Background(), "run-1", spec, env)

	if status != "passed" {
		t.Errorf("status = %q, want passed", status)
	}
	if notes != "" {
		t.Errorf("notes = %q, want empty", notes)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	for i, ev := range events {
		if ev.StepIndex != i {
			t.Errorf("events[%d].StepIndex = %d, want %d", i, ev.StepIndex, i)
		}
		if !ev.Success || ev.Error != "" {
			t.Errorf("events[%d] = %+v, want Success=true Error=\"\"", i, ev)
		}
	}
	if events[0].Kind != "bola" || events[1].Kind != "ssrf" {
		t.Errorf("events kinds = [%s %s], want [bola ssrf]", events[0].Kind, events[1].Kind)
	}
}

func TestRunSteps_OneStepFails_StatusFailedButAllStepsRun(t *testing.T) {
	disp := &fakeDispatcher{sequence: []dispatchResult{
		{success: true},
		{success: false, err: errors.New("dispatch boom")},
		{success: true},
	}}
	e := &Executor{dispatcher: disp, log: zaptest.NewLogger(t)}
	spec := specWithSteps(StepSpec{Kind: "bola"}, StepSpec{Kind: "ssrf"}, StepSpec{Kind: "misconfig"})
	env := &db.Environment{TargetURL: "http://target.example"}

	events, status, notes := e.runSteps(context.Background(), "run-2", spec, env)

	if status != "failed" {
		t.Errorf("status = %q, want failed", status)
	}
	if notes != "" {
		t.Errorf("notes = %q, want empty (failed status carries no note)", notes)
	}
	if len(events) != 3 {
		t.Fatalf("len(events) = %d, want 3 (a failed step must not abort remaining steps)", len(events))
	}
	if events[1].Error != "dispatch boom" {
		t.Errorf("events[1].Error = %q, want %q", events[1].Error, "dispatch boom")
	}
	if events[1].Success {
		t.Errorf("events[1].Success = true, want false")
	}
	// The step after the failure must still have been dispatched.
	if !events[2].Success {
		t.Errorf("events[2].Success = false, want true (steps after a failure still run)")
	}
}

func TestRunSteps_ContextCancelledMidLoop_StopsEarlyWithErrorStatus(t *testing.T) {
	disp := &fakeDispatcher{sequence: []dispatchResult{{success: true}}}
	e := &Executor{dispatcher: disp, log: zaptest.NewLogger(t)}
	// Three steps queued, but we cancel the context before calling runSteps
	// so the very first ctx.Err() check aborts the loop.
	spec := specWithSteps(StepSpec{Kind: "bola"}, StepSpec{Kind: "ssrf"}, StepSpec{Kind: "misconfig"})
	env := &db.Environment{TargetURL: "http://target.example"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	events, status, notes := e.runSteps(ctx, "run-3", spec, env)

	if status != "error" {
		t.Errorf("status = %q, want error", status)
	}
	if notes == "" {
		t.Error("expected a non-empty note explaining the early abort")
	}
	if len(events) != 0 {
		t.Errorf("len(events) = %d, want 0 (loop must abort before dispatching anything)", len(events))
	}
	if len(disp.calls) != 0 {
		t.Errorf("dispatcher was called %d times, want 0", len(disp.calls))
	}
}

func TestRunSteps_ContextCancelledBetweenSteps_PartialEvents(t *testing.T) {
	// A dispatcher that cancels the context as a side effect of its first
	// call lets us deterministically exercise the "cancelled between steps"
	// branch (as opposed to cancelled-before-the-loop-even-starts).
	ctx, cancel := context.WithCancel(context.Background())
	disp := &cancelOnFirstCallDispatcher{cancel: cancel}
	e := &Executor{dispatcher: disp, log: zaptest.NewLogger(t)}
	spec := specWithSteps(StepSpec{Kind: "bola"}, StepSpec{Kind: "ssrf"})
	env := &db.Environment{TargetURL: "http://target.example"}

	events, status, notes := e.runSteps(ctx, "run-4", spec, env)

	if status != "error" {
		t.Errorf("status = %q, want error", status)
	}
	if notes == "" {
		t.Error("expected a non-empty note")
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1 (first step dispatched, second aborted)", len(events))
	}
}

type cancelOnFirstCallDispatcher struct {
	cancel context.CancelFunc
	calls  int
}

func (c *cancelOnFirstCallDispatcher) Dispatch(_ context.Context, _ StepSpec, _ string) (bool, error) {
	c.calls++
	c.cancel()
	return true, nil
}

func TestRunSteps_EmptySteps(t *testing.T) {
	disp := &fakeDispatcher{}
	e := &Executor{dispatcher: disp, log: zaptest.NewLogger(t)}
	spec := specWithSteps()
	env := &db.Environment{TargetURL: "http://target.example"}

	events, status, notes := e.runSteps(context.Background(), "run-5", spec, env)

	if status != "passed" {
		t.Errorf("status = %q, want passed for zero steps", status)
	}
	if notes != "" {
		t.Errorf("notes = %q, want empty", notes)
	}
	if len(events) != 0 {
		t.Errorf("len(events) = %d, want 0", len(events))
	}
}

// ---------------------------------------------------------------------------
// waitForDetection
// ---------------------------------------------------------------------------

func TestWaitForDetection_Detected(t *testing.T) {
	det := &DetectionEvent{Platform: "openscrub", AlertID: "a1", Latency: 123}
	e := &Executor{monitor: &fakeMonitor{event: det}, log: zaptest.NewLogger(t)}

	detected, events, latencyMs := e.waitForDetection(context.Background(), "run-6")

	if !detected {
		t.Error("expected detected=true")
	}
	if len(events) != 1 || events[0].AlertID != "a1" {
		t.Errorf("events = %+v, want a single event with AlertID=a1", events)
	}
	if latencyMs == nil || *latencyMs != 123 {
		t.Errorf("latencyMs = %v, want pointer to 123", latencyMs)
	}
}

func TestWaitForDetection_MonitorError(t *testing.T) {
	e := &Executor{monitor: &fakeMonitor{err: errors.New("monitor unreachable")}, log: zaptest.NewLogger(t)}

	detected, events, latencyMs := e.waitForDetection(context.Background(), "run-7")

	if detected {
		t.Error("expected detected=false on monitor error")
	}
	if len(events) != 0 {
		t.Errorf("events = %+v, want empty", events)
	}
	if latencyMs != nil {
		t.Errorf("latencyMs = %v, want nil", latencyMs)
	}
}

func TestWaitForDetection_TimesOut(t *testing.T) {
	// No event and no error scripted: fakeMonitor blocks on its context,
	// which waitForDetection bounds to 30s — use a short parent-context
	// timeout so this test completes quickly rather than waiting 30s.
	e := &Executor{monitor: &fakeMonitor{}, log: zaptest.NewLogger(t)}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	detected, events, latencyMs := e.waitForDetection(ctx, "run-8")

	if detected {
		t.Error("expected detected=false on timeout")
	}
	if len(events) != 0 {
		t.Errorf("events = %+v, want empty", events)
	}
	if latencyMs != nil {
		t.Errorf("latencyMs = %v, want nil", latencyMs)
	}
}

func TestWaitForDetection_NilEventNilErrTreatedAsNoDetection(t *testing.T) {
	// A pathological monitor implementation could return (nil, nil). This
	// must not be misread as "detected" — it should behave like "no
	// detection" without panicking on a nil DetectionEvent dereference.
	e := &Executor{monitor: &nilEventMonitor{}, log: zaptest.NewLogger(t)}

	detected, events, latencyMs := e.waitForDetection(context.Background(), "run-9")

	if detected {
		t.Error("expected detected=false for (nil, nil) monitor result")
	}
	if len(events) != 0 {
		t.Errorf("events = %+v, want empty", events)
	}
	if latencyMs != nil {
		t.Errorf("latencyMs = %v, want nil", latencyMs)
	}
}

type nilEventMonitor struct{}

func (nilEventMonitor) WaitForDetection(context.Context) (*DetectionEvent, error) {
	return nil, nil
}

// TestRunSteps_DispatcherBlocksUntilContextCancelled_RecordsErrorEvent covers
// the case where a step's Dispatch call itself blocks until the context
// expires (as opposed to runSteps observing ctx.Err() before even calling
// Dispatch). The step must still be recorded as a failed AttackEvent, with
// status "failed" rather than "error" — the early-abort "error" status is
// reserved for steps skipped entirely because the context was already dead
// before Dispatch was invoked.
func TestRunSteps_DispatcherBlocksUntilContextCancelled_RecordsErrorEvent(t *testing.T) {
	e := &Executor{dispatcher: blockingDispatcher{}, log: zaptest.NewLogger(t)}
	spec := specWithSteps(StepSpec{Kind: "bola"})
	env := &db.Environment{TargetURL: "http://target.example"}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	events, status, _ := e.runSteps(ctx, "run-10", spec, env)

	if status != "failed" {
		t.Errorf("status = %q, want failed", status)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if events[0].Error == "" {
		t.Error("expected events[0].Error to be set from ctx.Err()")
	}
}
