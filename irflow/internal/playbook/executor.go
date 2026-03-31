package playbook

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// Executor runs playbook steps against an incident.
type Executor struct {
	logger *zap.Logger
	// citadel *citadel.Client // TODO: CITADEL integration for Kerkese submission
	// store   Store           // TODO: persistence for executions
}

func NewExecutor(logger *zap.Logger) *Executor {
	return &Executor{logger: logger}
}

// Execute runs a playbook against an incident.
func (e *Executor) Execute(ctx context.Context, pb *Playbook, incidentID string) (*Execution, error) {
	e.logger.Info("starting playbook execution",
		zap.String("playbook", pb.Name),
		zap.String("incident", incidentID),
	)

	exec := &Execution{
		PlaybookID:  pb.ID,
		IncidentID:  incidentID,
		Status:      ExecStatusRunning,
		CurrentStep: "",
	}

	for _, step := range pb.Steps {
		exec.CurrentStep = step.ID
		result, err := e.executeStep(ctx, &step, incidentID)
		if err != nil {
			exec.Status = ExecStatusFailed
			return exec, fmt.Errorf("step %s failed: %w", step.Name, err)
		}
		exec.StepResults = append(exec.StepResults, *result)
	}

	exec.Status = ExecStatusCompleted
	return exec, nil
}

func (e *Executor) executeStep(ctx context.Context, step *Step, incidentID string) (*StepResult, error) {
	e.logger.Info("executing step", zap.String("step", step.Name), zap.String("type", string(step.Type)))

	switch step.Type {
	case StepTypeAction:
		return e.executeAction(ctx, step, incidentID)
	case StepTypeNotify:
		return e.executeNotify(ctx, step, incidentID)
	case StepTypeWait:
		return e.executeWait(ctx, step)
	case StepTypeEnrich:
		return e.executeEnrich(ctx, step, incidentID)
	case StepTypeScan:
		return e.executeScan(ctx, step, incidentID)
	default:
		return nil, fmt.Errorf("unknown step type: %s", step.Type)
	}
}

// TODO: implement each step executor
func (e *Executor) executeAction(ctx context.Context, step *Step, incidentID string) (*StepResult, error) {
	// Submit Kerkese to CITADEL MARSHAL
	return &StepResult{StepID: step.ID, Status: "success", Output: "action submitted"}, nil
}

func (e *Executor) executeNotify(ctx context.Context, step *Step, incidentID string) (*StepResult, error) {
	// Send notification via configured channel
	return &StepResult{StepID: step.ID, Status: "success", Output: "notification sent"}, nil
}

func (e *Executor) executeWait(ctx context.Context, step *Step) (*StepResult, error) {
	// Wait for condition or timeout
	return &StepResult{StepID: step.ID, Status: "success", Output: "wait completed"}, nil
}

func (e *Executor) executeEnrich(ctx context.Context, step *Step, incidentID string) (*StepResult, error) {
	// Pull IOCs from ThreatFlow
	return &StepResult{StepID: step.ID, Status: "success", Output: "enrichment complete"}, nil
}

func (e *Executor) executeScan(ctx context.Context, step *Step, incidentID string) (*StepResult, error) {
	// Trigger APIGuard re-scan
	return &StepResult{StepID: step.ID, Status: "success", Output: "scan triggered"}, nil
}
