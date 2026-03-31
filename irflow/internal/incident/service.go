package incident

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
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
}

// ListOptions controls pagination and filtering for incident listing.
type ListOptions struct {
	Page     int
	PerPage  int
	Status   string
	Severity string
	Source   string
}

// Service orchestrates incident lifecycle with CITADEL governance.
type Service struct {
	store Store
	// citadel *citadel.Client  // TODO: wire CITADEL client
	// nis2    *nis2.Client     // TODO: wire NIS2 client
}

// NewService creates a new incident service backed by the given store.
func NewService(store Store) *Service {
	return &Service{store: store}
}

// idCounter is an atomic counter to guarantee uniqueness when multiple IDs
// are generated within the same nanosecond.
var idCounter atomic.Uint64

// generateID produces a simple unique identifier. In production this should
// use a proper UUID library (e.g. google/uuid).
func generateID() string {
	seq := idCounter.Add(1)
	return fmt.Sprintf("inc-%d-%d", time.Now().UnixNano(), seq)
}

// Create opens a new incident record.
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

	// Determine NIS2 notification requirement based on severity threshold.
	if threshold, ok := NIS2Thresholds[inc.Severity]; ok && threshold > 0 {
		inc.NIS2NotifyRequired = true
	}

	if err := s.store.Create(ctx, inc); err != nil {
		return nil, fmt.Errorf("creating incident: %w", err)
	}
	return inc, nil
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

	// Apply patches.
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

// SubmitAction records a governed action against an incident.
func (s *Service) SubmitAction(ctx context.Context, incidentID string, req *SubmitActionRequest) (*IncidentAction, error) {
	// TODO: submit Kerkese to CITADEL MARSHAL
	// TODO: verify SoD via CITADEL (operator != verifier) — see CITADEL integration
	// TODO: log to WORM
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
	if err := s.store.AddAction(ctx, action); err != nil {
		return nil, fmt.Errorf("adding action: %w", err)
	}
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
	ErrNotFound          = fmt.Errorf("incident not found")
	ErrInvalidTransition = fmt.Errorf("invalid status transition")
)
