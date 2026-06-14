package incident

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/metrics"
)

// Store defines the persistence interface for incidents.
type Store interface {
	Create(ctx context.Context, inc *Incident) error
	Get(ctx context.Context, id string) (*Incident, error)
	List(ctx context.Context, opts ListOptions) ([]Incident, int, error)
	Update(ctx context.Context, inc *Incident) error
	Delete(ctx context.Context, id string) error
	AddAction(ctx context.Context, action *IncidentAction) error
	ListActions(ctx context.Context, incidentID string) ([]IncidentAction, error)
	AddIOC(ctx context.Context, ioc *IOCEnrichment) error
	ListIOCs(ctx context.Context, incidentID string) ([]IOCEnrichment, error)
	GetTimeline(ctx context.Context, incidentID string) ([]TimelineEntry, error)
	Stats(ctx context.Context) (*Stats, error)
}

// ListOptions controls pagination and filtering for incident listing.
type ListOptions struct {
	Page     int
	PerPage  int
	Status   string
	Severity string
	Source   string
}

// Service orchestrates incident lifecycle with optional CITADEL and NIS2
// Compass integration. All governance integrations are optional: when a
// client is nil the corresponding step is skipped with a warning log.
type Service struct {
	store   Store
	marshal MarshalClient
	worm    WORMClient
	nis2    NIS2Client
	logger  *zap.Logger
	metrics *metrics.Metrics
}

// ServiceOption configures optional dependencies.
type ServiceOption func(*Service)

// WithMarshal enables CITADEL MARSHAL evaluation on SubmitAction.
func WithMarshal(c MarshalClient) ServiceOption { return func(s *Service) { s.marshal = c } }

// WithWORM enables CITADEL WORM audit-trail emission on incident lifecycle events.
func WithWORM(c WORMClient) ServiceOption { return func(s *Service) { s.worm = c } }

// WithNIS2 enables NIS2 Compass notifications on regulatory-significant incidents.
func WithNIS2(c NIS2Client) ServiceOption { return func(s *Service) { s.nis2 = c } }

// WithLogger supplies a zap logger. A nop logger is used by default.
func WithLogger(l *zap.Logger) ServiceOption { return func(s *Service) { s.logger = l } }

// WithMetrics wires a metrics recorder. Safe to pass nil (no-op).
func WithMetrics(m *metrics.Metrics) ServiceOption { return func(s *Service) { s.metrics = m } }

// NewService creates a new incident service backed by the given store.
// Functional options wire optional governance integrations.
func NewService(store Store, opts ...ServiceOption) *Service {
	s := &Service{store: store, logger: zap.NewNop()}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// idCounter is an atomic counter to guarantee uniqueness when multiple IDs
// are generated within the same nanosecond.
var idCounter atomic.Uint64

func generateID() string {
	seq := idCounter.Add(1)
	return fmt.Sprintf("inc-%d-%d", time.Now().UnixNano(), seq)
}

// Create opens a new incident record. If WORM is configured, the creation is
// anchored in the audit chain. If NIS2 is configured and the incident is
// regulatory-significant, Compass is notified asynchronously (so a slow NIS2
// API never blocks the HTTP response).
func (s *Service) Create(ctx context.Context, req *CreateIncidentRequest) (*Incident, error) {
	now := time.Now().UTC()
	inc := &Incident{
		ID:          generateID(),
		Title:       req.Title,
		Description: req.Description,
		Severity:    req.Severity,
		Status:      StatusOpen,
		Source:      req.Source,
		SourceRef:   req.SourceRef,
		ProjectID:   req.ProjectID,
		CommanderID: req.CommanderID,
		LeadID:      req.LeadID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if inc.Source == "" {
		inc.Source = SourceManual
	}
	if threshold, ok := NIS2Thresholds[inc.Severity]; ok && threshold > 0 {
		inc.NIS2NotifyRequired = true
	}

	if err := s.store.Create(ctx, inc); err != nil {
		return nil, fmt.Errorf("creating incident: %w", err)
	}
	s.metrics.IncidentCreated(string(inc.Severity), string(inc.Source))

	// Anchor the creation in WORM. A failure here is logged but not fatal —
	// the incident exists locally and operators can retry anchoring later.
	if s.worm != nil {
		payload, _ := json.Marshal(map[string]any{
			"incident_id": inc.ID,
			"title":       inc.Title,
			"severity":    inc.Severity,
			"source":      inc.Source,
			"source_ref":  inc.SourceRef,
		})
		receipt, err := s.worm.Emit(ctx, WORMEvent{
			Source:    "irflow",
			EventType: "incident.created",
			ProjectID: inc.ProjectID,
			Payload:   payload,
		})
		if err != nil {
			s.metrics.GovernanceCall("citadel_worm", "failure")
			s.logger.Warn("worm emit failed for incident.created",
				zap.String("incident_id", inc.ID), zap.Error(err))
		} else {
			s.metrics.GovernanceCall("citadel_worm", "success")
			inc.WORMEntryID = receipt.WORMEntryID
			if updateErr := s.store.Update(ctx, inc); updateErr != nil {
				s.logger.Warn("failed to persist worm entry id",
					zap.String("incident_id", inc.ID), zap.Error(updateErr))
			}
		}
	}

	// NIS2 notification runs async — a slow Compass must never block the
	// primary incident-creation path.
	if s.nis2 != nil && inc.NIS2NotifyRequired {
		go s.notifyNIS2Async(*inc)
	}

	return inc, nil
}

func (s *Service) notifyNIS2Async(inc Incident) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.nis2.NotifyIncident(ctx, &inc); err != nil {
		s.metrics.GovernanceCall("nis2", "failure")
		s.logger.Warn("nis2 notify failed",
			zap.String("incident_id", inc.ID), zap.Error(err))
		return
	}
	s.metrics.GovernanceCall("nis2", "success")

	now := time.Now().UTC()
	inc.NIS2NotifiedAt = &now
	inc.UpdatedAt = now
	if err := s.store.Update(ctx, &inc); err != nil {
		s.logger.Warn("failed to persist nis2_notified_at",
			zap.String("incident_id", inc.ID), zap.Error(err))
	}
}

// Get retrieves a single incident by ID.
func (s *Service) Get(ctx context.Context, id string) (*Incident, error) {
	return s.store.Get(ctx, id)
}

// List returns a paginated, filtered list of incidents.
func (s *Service) List(ctx context.Context, page, perPage int, status, severity, source string) ([]Incident, int, error) {
	opts := ListOptions{
		Page:     page,
		PerPage:  perPage,
		Status:   status,
		Severity: severity,
		Source:   source,
	}
	return s.store.List(ctx, opts)
}

// Patch applies a partial update to an existing incident.
func (s *Service) Patch(ctx context.Context, id string, req *PatchIncidentRequest) (*Incident, error) {
	inc, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Title != nil {
		inc.Title = *req.Title
	}
	if req.Description != nil {
		inc.Description = *req.Description
	}
	if req.Severity != nil {
		inc.Severity = *req.Severity
	}
	if req.Status != nil {
		if !isValidTransition(inc.Status, *req.Status) {
			return nil, ErrInvalidTransition
		}
		inc.Status = *req.Status

		now := time.Now().UTC()
		switch *req.Status {
		case StatusContained:
			inc.ContainedAt = &now
		case StatusClosed:
			inc.ClosedAt = &now
		}
	}
	if req.CommanderID != nil {
		inc.CommanderID = *req.CommanderID
	}
	if req.LeadID != nil {
		inc.LeadID = *req.LeadID
	}
	if req.RootCause != nil {
		inc.RootCause = *req.RootCause
	}
	if req.CorrectiveAction != nil {
		inc.CorrectiveAction = *req.CorrectiveAction
	}

	inc.UpdatedAt = time.Now().UTC()

	if err := s.store.Update(ctx, inc); err != nil {
		return nil, fmt.Errorf("updating incident: %w", err)
	}
	return inc, nil
}

// Delete removes an incident by ID.
func (s *Service) Delete(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}

// SubmitAction records a governed action against an incident. When a MARSHAL
// client is configured, CITADEL's five-gate engine evaluates the action
// before it is persisted; a REFUSE or HARD_STOP outcome prevents storage and
// surfaces a typed error.
func (s *Service) SubmitAction(ctx context.Context, incidentID string, req *SubmitActionRequest) (*IncidentAction, error) {
	action := &IncidentAction{
		ID:          fmt.Sprintf("act-%d", time.Now().UnixNano()),
		IncidentID:  incidentID,
		ActionType:  req.ActionType,
		OperatorID:  req.OperatorID,
		VerifierID:  req.VerifierID,
		Description: req.Description,
		Evidence:    req.Evidence,
		CreatedAt:   time.Now().UTC(),
	}

	if s.marshal != nil {
		// Look up the incident to scope the evaluation to the right project.
		inc, err := s.store.Get(ctx, incidentID)
		if err != nil {
			return nil, err
		}
		result, err := s.marshal.Evaluate(ctx, MarshalRequest{
			IncidentID:  incidentID,
			ActionType:  req.ActionType,
			Description: req.Description,
			OperatorID:  req.OperatorID,
			VerifierID:  req.VerifierID,
			ProjectID:   inc.ProjectID,
			Evidence:    req.Evidence,
		})
		if err != nil {
			s.metrics.GovernanceCall("citadel_marshal", "failure")
			s.logger.Error("marshal evaluate failed",
				zap.String("incident_id", incidentID), zap.Error(err))
			return nil, fmt.Errorf("marshal evaluate: %w", err)
		}
		s.metrics.GovernanceCall("citadel_marshal", "success")

		action.MarshalDecision = result.Outcome
		action.WORMEntryID = result.WORMEntryID

		switch result.Outcome {
		case MarshalOutcomeHardStop:
			s.metrics.ActionSubmitted(MarshalOutcomeHardStop)
			return nil, fmt.Errorf("%w: %v", ErrMarshalHardStop, result.Reasons)
		case MarshalOutcomeRefuse:
			s.metrics.ActionSubmitted(MarshalOutcomeRefuse)
			return nil, fmt.Errorf("%w: %v", ErrMarshalRefused, result.Reasons)
		}
	}

	if err := s.store.AddAction(ctx, action); err != nil {
		return nil, fmt.Errorf("adding action: %w", err)
	}
	outcome := action.MarshalDecision
	if outcome == "" {
		outcome = "LOCAL"
	}
	s.metrics.ActionSubmitted(outcome)
	return action, nil
}

// AddIOC attaches an indicator of compromise to an incident.
func (s *Service) AddIOC(ctx context.Context, incidentID string, ioc *IOCEnrichment) (*IOCEnrichment, error) {
	ioc.ID = fmt.Sprintf("ioc-%d", time.Now().UnixNano())
	ioc.IncidentID = incidentID
	if ioc.CreatedAt.IsZero() {
		ioc.CreatedAt = time.Now().UTC()
	}
	if err := s.store.AddIOC(ctx, ioc); err != nil {
		return nil, fmt.Errorf("adding IOC: %w", err)
	}
	return ioc, nil
}

// ListIOCs returns all IOC enrichments for an incident.
func (s *Service) ListIOCs(ctx context.Context, incidentID string) ([]IOCEnrichment, error) {
	return s.store.ListIOCs(ctx, incidentID)
}

// GetTimeline returns the chronological timeline for an incident.
func (s *Service) GetTimeline(ctx context.Context, incidentID string) ([]TimelineEntry, error) {
	return s.store.GetTimeline(ctx, incidentID)
}

// Stats returns aggregated counts for the dashboard.
func (s *Service) Stats(ctx context.Context) (*Stats, error) {
	return s.store.Stats(ctx)
}

// isValidTransition checks if the status transition is allowed.
func isValidTransition(from, to Status) bool {
	allowed, ok := ValidTransitions[from]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == to {
			return true
		}
	}
	return false
}

// Sentinel errors.
var (
	ErrNotFound          = errors.New("incident not found")
	ErrInvalidTransition = errors.New("invalid status transition")
)
