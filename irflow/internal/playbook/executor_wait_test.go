package playbook

import (
	"context"
	"errors"
	"testing"
	"time"
)

// executeWait branch coverage: no-duration configured (skip), invalid
// duration string (error), successful completion, and context cancellation.

func TestExecuteWait_NoDurationConfigured_SkipsImmediately(t *testing.T) {
	e := newTestExecutor()
	step := &Step{ID: "w", Type: StepTypeWait, Config: map[string]interface{}{}}

	start := time.Now()
	out, err := e.executeWait(context.Background(), step)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "wait: no duration configured — skipping" {
		t.Errorf("output = %q, want the skip message", out)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("executeWait with no duration should return immediately, took %s", elapsed)
	}
}

func TestExecuteWait_InvalidDuration_ReturnsError(t *testing.T) {
	e := newTestExecutor()
	step := &Step{ID: "w", Type: StepTypeWait, Config: map[string]interface{}{"timeout": "not-a-duration"}}

	out, err := e.executeWait(context.Background(), step)
	if err == nil {
		t.Fatal("expected an error for an unparseable wait duration, got nil")
	}
	if out != "" {
		t.Errorf("output = %q, want empty on error", out)
	}
}

func TestExecuteWait_CompletesAfterDuration(t *testing.T) {
	e := newTestExecutor()
	step := &Step{ID: "w", Type: StepTypeWait, Config: map[string]interface{}{"timeout": "10ms"}}

	start := time.Now()
	out, err := e.executeWait(context.Background(), step)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed < 10*time.Millisecond {
		t.Errorf("executeWait returned before the configured duration elapsed: %s", elapsed)
	}
	if out != "waited 10ms" {
		t.Errorf("output = %q, want %q", out, "waited 10ms")
	}
}

func TestExecuteWait_ContextCancelledBeforeDurationElapses(t *testing.T) {
	e := newTestExecutor()
	step := &Step{ID: "w", Type: StepTypeWait, Config: map[string]interface{}{"timeout": "1h"}}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	out, err := e.executeWait(ctx, step)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if out != "" {
		t.Errorf("output = %q, want empty on cancellation", out)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("executeWait should return promptly on cancellation, took %s", elapsed)
	}
}
