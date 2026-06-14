package playbook

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/metrics"
)

// Store defines the persistence interface for playbooks and their executions.
type Store interface {
	Create(ctx context.Context, pb *Playbook) error
	Get(ctx context.Context, id string) (*Playbook, error)
	List(ctx context.Context, opts ListOptions) ([]Playbook, int, error)
	Update(ctx context.Context, pb *Playbook) error
	Delete(ctx context.Context, id string) error

	CreateExecution(ctx context.Context, exec *Execution) error
	GetExecution(ctx context.Context, id string) (*Execution, error)
	ListExecutions(ctx context.Context, playbookID string) ([]Execution, error)
	UpdateExecution(ctx context.Context, exec *Execution) error
}

// Service orchestrates playbook CRUD and execution.
type Service struct {
	store    Store
	executor *Executor
	logger   *zap.Logger
	metrics  *metrics.Metrics
}

// NewService creates a new playbook service.
func NewService(store Store, executor *Executor, logger *zap.Logger) *Service {
	return &Service{store: store, executor: executor, logger: logger}
}

// WithMetrics attaches a metrics recorder to the service. Safe to call with nil.
func (s *Service) WithMetrics(m *metrics.Metrics) *Service {
	s.metrics = m
	if s.executor != nil {
		s.executor.metrics = m
	}
	return s
}

var (
	playbookCounter  atomic.Uint64
	executionCounter atomic.Uint64
)

func generatePlaybookID() string {
	seq := playbookCounter.Add(1)
	return fmt.Sprintf("pb-%d-%d", time.Now().UnixNano(), seq)
}

func generateExecutionID() string {
	seq := executionCounter.Add(1)
	return fmt.Sprintf("exec-%d-%d", time.Now().UnixNano(), seq)
}

// Create registers a new playbook.
func (s *Service) Create(ctx context.Context, req *CreatePlaybookRequest) (*Playbook, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalid)
	}

	now := time.Now().UTC()
	pb := &Playbook{
		ID:          generatePlaybookID(),
		Name:        req.Name,
		Description: req.Description,
		Version:     req.Version,
		Status:      req.Status,
		Trigger:     req.Trigger,
		Steps:       req.Steps,
		CreatedBy:   req.CreatedBy,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if pb.Version == "" {
		pb.Version = "1.0"
	}
	if pb.Status == "" {
		pb.Status = PlaybookStatusDraft
	}

	if err := s.store.Create(ctx, pb); err != nil {
		return nil, fmt.Errorf("storing playbook: %w", err)
	}
	return pb, nil
}

// Get retrieves a single playbook.
func (s *Service) Get(ctx context.Context, id string) (*Playbook, error) {
	return s.store.Get(ctx, id)
}

// List returns a paginated list of playbooks.
func (s *Service) List(ctx context.Context, page, perPage int, status string) ([]Playbook, int, error) {
	if perPage <= 0 || perPage > 100 {
		perPage = 50
	}
	if page <= 0 {
		page = 1
	}
	return s.store.List(ctx, ListOptions{Page: page, PerPage: perPage, Status: status})
}

// Patch applies partial updates.
func (s *Service) Patch(ctx context.Context, id string, req *PatchPlaybookRequest) (*Playbook, error) {
	pb, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		pb.Name = *req.Name
	}
	if req.Description != nil {
		pb.Description = *req.Description
	}
	if req.Version != nil {
		pb.Version = *req.Version
	}
	if req.Status != nil {
		pb.Status = *req.Status
	}
	if req.Trigger != nil {
		pb.Trigger = *req.Trigger
	}
	if req.Steps != nil {
		pb.Steps = *req.Steps
	}
	pb.UpdatedAt = time.Now().UTC()

	if err := s.store.Update(ctx, pb); err != nil {
		return nil, fmt.Errorf("updating playbook: %w", err)
	}
	return pb, nil
}

// Delete removes a playbook.
func (s *Service) Delete(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}

// Execute launches a playbook run against an incident. The execution runs
// asynchronously; this method returns the Execution record in "pending" state
// immediately and the executor updates it to running → completed/failed via
// Store.UpdateExecution.
func (s *Service) Execute(ctx context.Context, playbookID, incidentID string) (*Execution, error) {
	pb, err := s.store.Get(ctx, playbookID)
	if err != nil {
		return nil, err
	}
	if pb.Status != PlaybookStatusActive {
		return nil, fmt.Errorf("%w: playbook is not active (status=%s)", ErrInvalid, pb.Status)
	}

	exec := &Execution{
		ID:         generateExecutionID(),
		PlaybookID: playbookID,
		IncidentID: incidentID,
		Status:     ExecStatusPending,
		StartedAt:  time.Now().UTC(),
	}
	if err := s.store.CreateExecution(ctx, exec); err != nil {
		return nil, fmt.Errorf("recording execution: %w", err)
	}

	// Run asynchronously. Detach the request context so cancellation of the
	// HTTP request does not kill the playbook run.
	go s.runExecution(pb, exec)

	return exec, nil
}

// GetExecution fetches an execution record.
func (s *Service) GetExecution(ctx context.Context, id string) (*Execution, error) {
	return s.store.GetExecution(ctx, id)
}

// ListExecutions returns all executions for a given playbook.
func (s *Service) ListExecutions(ctx context.Context, playbookID string) ([]Execution, error) {
	return s.store.ListExecutions(ctx, playbookID)
}

func (s *Service) runExecution(pb *Playbook, exec *Execution) {
	// Use a background context so graceful shutdown does not interrupt a
	// started playbook mid-step. The executor enforces per-step timeouts.
	bgCtx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
	defer cancel()

	exec.Status = ExecStatusRunning
	if err := s.store.UpdateExecution(bgCtx, exec); err != nil {
		s.logger.Error("failed to mark execution running",
			zap.String("execution_id", exec.ID), zap.Error(err))
	}

	result := s.executor.Run(bgCtx, pb, exec)

	now := time.Now().UTC()
	result.CompletedAt = &now
	if err := s.store.UpdateExecution(bgCtx, result); err != nil {
		s.logger.Error("failed to persist execution result",
			zap.String("execution_id", result.ID), zap.Error(err))
	}
	s.metrics.PlaybookExecuted(string(result.Status))
}
