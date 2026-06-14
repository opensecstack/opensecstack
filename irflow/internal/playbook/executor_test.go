package playbook

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newTestExecutor() *Executor {
	return NewExecutor(zap.NewNop())
}

func TestExecutor_Empty(t *testing.T) {
	e := newTestExecutor()
	exec := &Execution{ID: "e1", PlaybookID: "pb1", IncidentID: "inc1"}
	result := e.Run(context.Background(), &Playbook{ID: "pb1"}, exec)

	if result.Status != ExecStatusCompleted {
		t.Fatalf("empty playbook: status = %s, want %s", result.Status, ExecStatusCompleted)
	}
	if len(result.StepResults) != 0 {
		t.Errorf("empty playbook: got %d step results, want 0", len(result.StepResults))
	}
}

func TestExecutor_LinearSuccess(t *testing.T) {
	e := newTestExecutor()
	pb := &Playbook{
		ID: "pb1",
		Steps: []Step{
			{ID: "a", Name: "A", Type: StepTypeAction, OnSuccess: "b"},
			{ID: "b", Name: "B", Type: StepTypeNotify, OnSuccess: "c"},
			{ID: "c", Name: "C", Type: StepTypeAction},
		},
	}
	exec := &Execution{ID: "e1", PlaybookID: "pb1", IncidentID: "inc1"}
	result := e.Run(context.Background(), pb, exec)

	if result.Status != ExecStatusCompleted {
		t.Fatalf("status = %s, want %s (error: %s)", result.Status, ExecStatusCompleted, result.Error)
	}
	if len(result.StepResults) != 3 {
		t.Fatalf("got %d step results, want 3", len(result.StepResults))
	}
	for i, sr := range result.StepResults {
		if sr.Status != "success" {
			t.Errorf("step %d: status = %s, want success", i, sr.Status)
		}
	}
}

func TestExecutor_OnSuccessBranching(t *testing.T) {
	// a → c (skipping b entirely)
	e := newTestExecutor()
	pb := &Playbook{
		ID: "pb1",
		Steps: []Step{
			{ID: "a", Name: "A", Type: StepTypeAction, OnSuccess: "c"},
			{ID: "b", Name: "B (should be skipped)", Type: StepTypeAction},
			{ID: "c", Name: "C", Type: StepTypeAction},
		},
	}
	result := e.Run(context.Background(), pb, &Execution{ID: "e1"})

	if len(result.StepResults) != 2 {
		t.Fatalf("got %d step results, want 2", len(result.StepResults))
	}
	if result.StepResults[0].StepID != "a" || result.StepResults[1].StepID != "c" {
		t.Errorf("wrong step order: %v", stepIDs(result.StepResults))
	}
}

func TestExecutor_OnFailureRecovery(t *testing.T) {
	// Use an unknown step type to force a failure, then recover via OnFailure.
	e := newTestExecutor()
	pb := &Playbook{
		ID: "pb1",
		Steps: []Step{
			{ID: "a", Name: "A", Type: StepType("bogus"), OnFailure: "recover"},
			{ID: "recover", Name: "Recover", Type: StepTypeNotify},
		},
	}
	result := e.Run(context.Background(), pb, &Execution{ID: "e1"})

	if result.Status != ExecStatusCompleted {
		t.Fatalf("status = %s, want %s", result.Status, ExecStatusCompleted)
	}
	if len(result.StepResults) != 2 {
		t.Fatalf("got %d step results, want 2", len(result.StepResults))
	}
	if result.StepResults[0].Status != "failed" {
		t.Errorf("step a should be failed, got %s", result.StepResults[0].Status)
	}
	if result.StepResults[1].Status != "success" {
		t.Errorf("recover step should be success, got %s", result.StepResults[1].Status)
	}
}

func TestExecutor_FailureWithoutFallback(t *testing.T) {
	e := newTestExecutor()
	pb := &Playbook{
		ID: "pb1",
		Steps: []Step{
			{ID: "a", Name: "A", Type: StepType("bogus")},
		},
	}
	result := e.Run(context.Background(), pb, &Execution{ID: "e1"})

	if result.Status != ExecStatusFailed {
		t.Fatalf("status = %s, want %s", result.Status, ExecStatusFailed)
	}
	if result.Error == "" {
		t.Error("expected Error to be populated")
	}
}

func TestExecutor_UnknownStepIDHalts(t *testing.T) {
	e := newTestExecutor()
	pb := &Playbook{
		ID: "pb1",
		Steps: []Step{
			{ID: "a", Name: "A", Type: StepTypeAction, OnSuccess: "does-not-exist"},
		},
	}
	result := e.Run(context.Background(), pb, &Execution{ID: "e1"})

	if result.Status != ExecStatusFailed {
		t.Fatalf("status = %s, want %s", result.Status, ExecStatusFailed)
	}
}

func TestExecutor_CycleProtection(t *testing.T) {
	// a → b → a (infinite loop until the maxStepsPerExecution guard fires)
	e := newTestExecutor()
	pb := &Playbook{
		ID: "pb1",
		Steps: []Step{
			{ID: "a", Name: "A", Type: StepTypeAction, OnSuccess: "b"},
			{ID: "b", Name: "B", Type: StepTypeAction, OnSuccess: "a"},
		},
	}
	result := e.Run(context.Background(), pb, &Execution{ID: "e1"})

	if result.Status != ExecStatusFailed {
		t.Fatalf("status = %s, want %s", result.Status, ExecStatusFailed)
	}
	if len(result.StepResults) != maxStepsPerExecution {
		t.Errorf("got %d step results, want %d (cycle cap)", len(result.StepResults), maxStepsPerExecution)
	}
}

func TestExecutor_WaitRespectsTimeout(t *testing.T) {
	// A wait step configured with 10s should time out when its step-level
	// Timeout is 20ms, producing a failed result (context deadline).
	e := newTestExecutor()
	pb := &Playbook{
		ID: "pb1",
		Steps: []Step{
			{
				ID:      "w",
				Name:    "wait",
				Type:    StepTypeWait,
				Timeout: "20ms",
				Config:  map[string]interface{}{"timeout": "10s"},
			},
		},
	}
	start := time.Now()
	result := e.Run(context.Background(), pb, &Execution{ID: "e1"})
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("wait took too long: %s (step timeout should have fired fast)", elapsed)
	}
	if result.Status != ExecStatusFailed {
		t.Fatalf("status = %s, want %s", result.Status, ExecStatusFailed)
	}
	if len(result.StepResults) != 1 || result.StepResults[0].Status != "failed" {
		t.Errorf("expected one failed step, got %+v", result.StepResults)
	}
}

func TestExecutor_InvalidStepTimeout(t *testing.T) {
	e := newTestExecutor()
	pb := &Playbook{
		ID: "pb1",
		Steps: []Step{
			{ID: "a", Name: "A", Type: StepTypeAction, Timeout: "not-a-duration"},
		},
	}
	result := e.Run(context.Background(), pb, &Execution{ID: "e1"})

	if result.Status != ExecStatusFailed {
		t.Fatalf("status = %s, want %s", result.Status, ExecStatusFailed)
	}
}

func TestExecutor_CancelledContext(t *testing.T) {
	e := newTestExecutor()
	pb := &Playbook{
		ID: "pb1",
		Steps: []Step{
			{ID: "a", Name: "A", Type: StepTypeAction, OnSuccess: "b"},
			{ID: "b", Name: "B", Type: StepTypeAction},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	result := e.Run(ctx, pb, &Execution{ID: "e1"})
	if result.Status != ExecStatusCancelled {
		t.Fatalf("status = %s, want %s", result.Status, ExecStatusCancelled)
	}
}

func stepIDs(results []StepResult) []string {
	ids := make([]string, len(results))
	for i, r := range results {
		ids[i] = r.StepID
	}
	return ids
}
