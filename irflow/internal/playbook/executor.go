package playbook

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/metrics"
)

// maxStepsPerExecution caps how many steps one execution may run — a
// defence-in-depth guard against cyclic playbooks (A → B → A) created by
// misconfigured on_success/on_failure pointers.
const maxStepsPerExecution = 100

// Executor runs the steps of a playbook against an incident. It traverses the
// step graph using OnSuccess / OnFailure pointers rather than linear
// iteration, honours per-step timeouts, and records one StepResult per step
// attempt onto the Execution.
//
// Step types that call external services (action, notify, enrich, scan) run
// in dry-run mode in v1.0.0 — they record structured StepResults so UIs and
// tests can observe progress, but they do not yet dispatch to CITADEL,
// ThreatFlow, or APIGuard. Real dispatchers will be injected in a future
// release without changing the executor's public contract.
type Executor struct {
	logger  *zap.Logger
	metrics *metrics.Metrics
}

// NewExecutor constructs an Executor backed by the given logger.
func NewExecutor(logger *zap.Logger) *Executor {
	return &Executor{logger: logger}
}

// Run executes the playbook, mutating exec in place. It returns the same
// *Execution pointer so callers can chain-persist the final state.
//
// Run never panics: individual step failures are captured as StepResult
// entries with status="failed" and the execution's Status reflects the
// overall outcome (completed | failed | cancelled).
func (e *Executor) Run(ctx context.Context, pb *Playbook, exec *Execution) *Execution {
	if len(pb.Steps) == 0 {
		exec.Status = ExecStatusCompleted
		return exec
	}

	stepMap := make(map[string]*Step, len(pb.Steps))
	for i := range pb.Steps {
		stepMap[pb.Steps[i].ID] = &pb.Steps[i]
	}

	e.logger.Info("executing playbook",
		zap.String("playbook_id", pb.ID),
		zap.String("playbook_name", pb.Name),
		zap.String("incident_id", exec.IncidentID),
		zap.Int("step_count", len(pb.Steps)),
	)

	currentID := pb.Steps[0].ID
	visited := 0
	failed := false

	for currentID != "" {
		if visited >= maxStepsPerExecution {
			exec.Error = fmt.Sprintf("execution aborted: exceeded %d steps (possible cycle)", maxStepsPerExecution)
			exec.Status = ExecStatusFailed
			return exec
		}

		step, ok := stepMap[currentID]
		if !ok {
			exec.Error = fmt.Sprintf("unknown step id: %s", currentID)
			exec.Status = ExecStatusFailed
			return exec
		}

		if err := ctx.Err(); err != nil {
			exec.Error = fmt.Sprintf("cancelled: %v", err)
			exec.Status = ExecStatusCancelled
			return exec
		}

		exec.CurrentStep = step.ID
		visited++

		result := e.runStep(ctx, step, exec.IncidentID)
		exec.StepResults = append(exec.StepResults, *result)

		if result.Status == "failed" {
			failed = true
			if step.OnFailure != "" {
				currentID = step.OnFailure
				continue
			}
			exec.Error = result.Error
			exec.Status = ExecStatusFailed
			return exec
		}

		currentID = step.OnSuccess
	}

	if failed {
		// Unlikely — a failure without on_failure returns above, but a
		// recovered failure path still counts as a partial failure.
		exec.Status = ExecStatusCompleted
		return exec
	}
	exec.Status = ExecStatusCompleted
	return exec
}

// runStep dispatches to the appropriate executor and wraps the call in a
// per-step timeout when step.Timeout is set (e.g. "5m", "15s").
func (e *Executor) runStep(ctx context.Context, step *Step, incidentID string) *StepResult {
	started := time.Now().UTC()
	result := &StepResult{StepID: step.ID, StartedAt: started}

	stepCtx := ctx
	if step.Timeout != "" {
		d, err := time.ParseDuration(step.Timeout)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("invalid timeout %q: %v", step.Timeout, err)
			result.EndedAt = time.Now().UTC()
			return result
		}
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}

	e.logger.Info("executing step",
		zap.String("step_id", step.ID),
		zap.String("step_name", step.Name),
		zap.String("step_type", string(step.Type)),
	)

	var output string
	var err error

	switch step.Type {
	case StepTypeAction:
		output, err = e.executeAction(stepCtx, step, incidentID)
	case StepTypeNotify:
		output, err = e.executeNotify(stepCtx, step, incidentID)
	case StepTypeWait:
		output, err = e.executeWait(stepCtx, step)
	case StepTypeEnrich:
		output, err = e.executeEnrich(stepCtx, step, incidentID)
	case StepTypeScan:
		output, err = e.executeScan(stepCtx, step, incidentID)
	case StepTypeConditional:
		output, err = e.executeConditional(stepCtx, step, incidentID)
	default:
		err = fmt.Errorf("unknown step type: %s", step.Type)
	}

	result.EndedAt = time.Now().UTC()
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		e.metrics.PlaybookStep(string(step.Type), "failed")
		return result
	}
	result.Status = "success"
	result.Output = output
	e.metrics.PlaybookStep(string(step.Type), "success")
	return result
}

// ---------------------------------------------------------------------------
// Step implementations
//
// These are dry-run bodies: they record the intent of each step in the
// returned StepResult but do not yet dispatch to CITADEL, ThreatFlow, or
// APIGuard. A future release will replace the bodies without changing the
// (inputs, outputs, error semantics) contract the Executor relies on.
// ---------------------------------------------------------------------------

func (e *Executor) executeAction(ctx context.Context, step *Step, incidentID string) (string, error) {
	actionType, _ := step.Config["action_type"].(string)
	return fmt.Sprintf("action %q on incident %s (dry-run)", actionType, incidentID), nil
}

func (e *Executor) executeNotify(ctx context.Context, step *Step, incidentID string) (string, error) {
	channel, _ := step.Config["channel"].(string)
	if channel == "" {
		if chans, ok := step.Config["channels"].([]interface{}); ok && len(chans) > 0 {
			channel = fmt.Sprint(chans[0])
		}
	}
	return fmt.Sprintf("notification queued for channel %q (dry-run)", channel), nil
}

// executeWait honours step.Config["timeout"] (duration string) and respects
// context cancellation. If no timeout is set it returns immediately.
func (e *Executor) executeWait(ctx context.Context, step *Step) (string, error) {
	waitStr, _ := step.Config["timeout"].(string)
	if waitStr == "" {
		return "wait: no duration configured — skipping", nil
	}
	d, err := time.ParseDuration(waitStr)
	if err != nil {
		return "", fmt.Errorf("invalid wait duration %q: %w", waitStr, err)
	}

	select {
	case <-time.After(d):
		return fmt.Sprintf("waited %s", d), nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (e *Executor) executeEnrich(ctx context.Context, step *Step, incidentID string) (string, error) {
	sources, _ := step.Config["sources"].([]interface{})
	return fmt.Sprintf("enrichment requested from %d source(s) for incident %s (dry-run)", len(sources), incidentID), nil
}

func (e *Executor) executeScan(ctx context.Context, step *Step, incidentID string) (string, error) {
	target, _ := step.Config["target"].(string)
	return fmt.Sprintf("scan triggered against %q for incident %s (dry-run)", target, incidentID), nil
}

// executeConditional is a trivial pass-through until a CEL evaluator lands.
// It will then evaluate step.Config["expression"] against the incident
// context and drive branching via OnSuccess / OnFailure.
func (e *Executor) executeConditional(ctx context.Context, step *Step, incidentID string) (string, error) {
	expr, _ := step.Config["expression"].(string)
	return fmt.Sprintf("conditional %q evaluated (dry-run)", expr), nil
}
