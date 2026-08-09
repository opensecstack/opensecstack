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
	CreatePendingAction(ctx context.Context, pa *PendingAction) error
	GetPendingAction(ctx context.Context, id string) (*PendingAction, error)
	UpdatePendingAction(ctx context.Context, pa *PendingAction) error
	ListPendingActions(ctx context.Context, incidentID string) ([]PendingAction, error)
	AddIOC(ctx context.Context, ioc *IOCEnrichment) error
	ListIOCs(ctx context.Context, incidentID string) ([]IOCEnrichment, error)
	AddTimelineEntry(ctx context.Context, entry *TimelineEntry) error
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

// WithMarshal enables CITADEL MARSHAL evaluation on ApproveAction.
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

// ProposeAction records an Operator's proposal for a governed action against
// an incident. The proposal is NOT evaluated by CITADEL and does NOT create
// an IncidentAction yet — it is persisted as a PendingAction awaiting a
// SECOND, distinct authenticated user's decision via ApproveAction or
// RejectAction. operatorUserID/operatorRole must come from the caller's own
// authenticated session (see auth.ClaimsFromContext), never from
// client-supplied request fields — that is the entire point of this
// two-step flow.
func (s *Service) ProposeAction(ctx context.Context, incidentID, operatorUserID, operatorRole string, req *ProposeActionRequest) (*PendingAction, error) {
	if _, err := s.store.Get(ctx, incidentID); err != nil {
		return nil, err
	}

	pa := &PendingAction{
		ID:             fmt.Sprintf("pact-%d-%d", time.Now().UnixNano(), idCounter.Add(1)),
		IncidentID:     incidentID,
		ActionType:     req.ActionType,
		Description:    req.Description,
		Evidence:       req.Evidence,
		OperatorUserID: operatorUserID,
		OperatorRole:   operatorRole,
		Status:         PendingActionStatusPending,
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.store.CreatePendingAction(ctx, pa); err != nil {
		return nil, fmt.Errorf("creating pending action: %w", err)
	}
	return pa, nil
}

// ApproveAction lets a SECOND, distinct authenticated user (the Verifier)
// approve a pending action. verifierUserID/verifierRole must come from the
// approver's own authenticated session, and verifierToken must be their own
// raw sinauth bearer token — never anything supplied by the Operator who
// proposed the action. When a MARSHAL client is configured, CITADEL's
// five-gate engine evaluates the action (with both real user IDs and the
// Verifier's real token) before it is persisted; a REFUSE or HARD_STOP
// outcome prevents storage and surfaces a typed error.
func (s *Service) ApproveAction(ctx context.Context, incidentID, pendingActionID, verifierUserID, verifierRole, verifierToken string) (*IncidentAction, error) {
	pa, err := s.store.GetPendingAction(ctx, pendingActionID)
	if err != nil {
		return nil, err
	}
	if pa.IncidentID != incidentID {
		return nil, ErrPendingActionNotFound
	}
	if pa.Status != PendingActionStatusPending {
		return nil, ErrAlreadyDecided
	}
	// Separation of Duties, enforced cryptographically: the Verifier must be
	// a genuinely distinct authenticated identity from the Operator who
	// proposed the action. Both sides are real sinauth UUIDs derived from
	// two separate authenticated HTTP requests — never a client-supplied
	// string that could collide by construction.
	if verifierUserID == pa.OperatorUserID {
		return nil, ErrSelfApproval
	}

	now := time.Now().UTC()
	pa.VerifierUserID = verifierUserID
	pa.VerifierRole = verifierRole

	action := &IncidentAction{
		ID:          fmt.Sprintf("act-%d-%d", now.UnixNano(), idCounter.Add(1)),
		IncidentID:  incidentID,
		ActionType:  pa.ActionType,
		OperatorID:  pa.OperatorUserID,
		VerifierID:  verifierUserID,
		Description: pa.Description,
		Evidence:    pa.Evidence,
		CreatedAt:   now,
	}

	if s.marshal != nil {
		// Look up the incident to scope the evaluation to the right project.
		inc, err := s.store.Get(ctx, incidentID)
		if err != nil {
			return nil, err
		}
		result, err := s.marshal.Evaluate(ctx, MarshalRequest{
			IncidentID:   incidentID,
			ActionType:   pa.ActionType,
			Description:  pa.Description,
			OperatorID:   pa.OperatorUserID,
			OperatorRole: pa.OperatorRole,
			VerifierID:   verifierUserID,
			VerifierRole: verifierRole,
			ProjectID:    inc.ProjectID,
			Evidence:     pa.Evidence,
			// ActorToken is intentionally left empty here: the Operator's
			// original bearer token from the propose step is never retained
			// — a bearer token is a short-lived secret (citadel ADR-005),
			// and persisting it in pending_actions across an arbitrarily
			// long approval window would reintroduce the kind of risk this
			// rollout exists to close. CITADEL's Gate 1 treats a missing
			// ActorToken as a non-blocking WARN while
			// citadel.enforce_signatures stays false (its documented
			// soft-mode rollout behaviour) — the Operator's identity itself
			// is still real, derived from their own authenticated session
			// at proposal time, not from client-supplied input.
			VerifierToken: verifierToken,
		})
		if err != nil {
			s.metrics.GovernanceCall("citadel_marshal", "failure")
			s.logger.Error("marshal evaluate failed",
				zap.String("incident_id", incidentID),
				zap.String("pending_action_id", pa.ID), zap.Error(err))
			return nil, fmt.Errorf("marshal evaluate: %w", err)
		}
		s.metrics.GovernanceCall("citadel_marshal", "success")

		action.MarshalDecision = result.Outcome
		action.WORMEntryID = result.WORMEntryID
		pa.MarshalDecision = result.Outcome
		pa.WORMEntryID = result.WORMEntryID
		pa.Reasons = result.Reasons

		switch result.Outcome {
		case MarshalOutcomeHardStop:
			pa.Status = PendingActionStatusBlocked
			pa.DecidedAt = &now
			if uErr := s.store.UpdatePendingAction(ctx, pa); uErr != nil {
				s.logger.Warn("failed to persist blocked pending action",
					zap.String("pending_action_id", pa.ID), zap.Error(uErr))
			}
			s.metrics.ActionSubmitted(MarshalOutcomeHardStop)
			return nil, fmt.Errorf("%w: %v", ErrMarshalHardStop, result.Reasons)
		case MarshalOutcomeRefuse:
			pa.Status = PendingActionStatusRefused
			pa.DecidedAt = &now
			if uErr := s.store.UpdatePendingAction(ctx, pa); uErr != nil {
				s.logger.Warn("failed to persist refused pending action",
					zap.String("pending_action_id", pa.ID), zap.Error(uErr))
			}
			s.metrics.ActionSubmitted(MarshalOutcomeRefuse)
			return nil, fmt.Errorf("%w: %v", ErrMarshalRefused, result.Reasons)
		}
	}

	if err := s.store.AddAction(ctx, action); err != nil {
		return nil, fmt.Errorf("adding action: %w", err)
	}

	pa.Status = PendingActionStatusApproved
	pa.ActionID = action.ID
	pa.DecidedAt = &now
	if err := s.store.UpdatePendingAction(ctx, pa); err != nil {
		// The IncidentAction is already durably stored — this is a
		// best-effort bookkeeping update on the proposal record, not fatal.
		s.logger.Warn("failed to persist approved pending action",
			zap.String("pending_action_id", pa.ID), zap.Error(err))
	}

	outcome := action.MarshalDecision
	if outcome == "" {
		outcome = "LOCAL"
	}
	s.metrics.ActionSubmitted(outcome)
	return action, nil
}

// RejectAction lets a SECOND, distinct authenticated user (the Verifier)
// reject a pending action outright, without ever submitting it to CITADEL.
func (s *Service) RejectAction(ctx context.Context, incidentID, pendingActionID, verifierUserID, verifierRole string) (*PendingAction, error) {
	pa, err := s.store.GetPendingAction(ctx, pendingActionID)
	if err != nil {
		return nil, err
	}
	if pa.IncidentID != incidentID {
		return nil, ErrPendingActionNotFound
	}
	if pa.Status != PendingActionStatusPending {
		return nil, ErrAlreadyDecided
	}
	if verifierUserID == pa.OperatorUserID {
		return nil, ErrSelfApproval
	}

	now := time.Now().UTC()
	pa.VerifierUserID = verifierUserID
	pa.VerifierRole = verifierRole
	pa.Status = PendingActionStatusRejected
	pa.DecidedAt = &now
	if err := s.store.UpdatePendingAction(ctx, pa); err != nil {
		return nil, fmt.Errorf("updating pending action: %w", err)
	}
	return pa, nil
}

// ListPendingActions returns every pending action proposed against an
// incident, regardless of status.
func (s *Service) ListPendingActions(ctx context.Context, incidentID string) ([]PendingAction, error) {
	return s.store.ListPendingActions(ctx, incidentID)
}

// GetPendingAction retrieves a single pending action, scoped to incidentID so
// a caller cannot probe another incident's pending action by ID alone.
func (s *Service) GetPendingAction(ctx context.Context, incidentID, pendingActionID string) (*PendingAction, error) {
	pa, err := s.store.GetPendingAction(ctx, pendingActionID)
	if err != nil {
		return nil, err
	}
	if pa.IncidentID != incidentID {
		return nil, ErrPendingActionNotFound
	}
	return pa, nil
}

// AddIOC attaches an indicator of compromise to an incident.
func (s *Service) AddIOC(ctx context.Context, incidentID string, ioc *IOCEnrichment) (*IOCEnrichment, error) {
	ioc.ID = fmt.Sprintf("ioc-%d-%d", time.Now().UnixNano(), idCounter.Add(1))
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

// AddTimelineEntry appends a chronological event to an incident's timeline.
// The incident must already exist; callers that only have an incident ID
// from an inbound webhook should Get() it first to confirm a match.
func (s *Service) AddTimelineEntry(ctx context.Context, incidentID string, entry *TimelineEntry) (*TimelineEntry, error) {
	entry.ID = fmt.Sprintf("tl-%d-%d", time.Now().UnixNano(), idCounter.Add(1))
	entry.IncidentID = incidentID
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	if err := s.store.AddTimelineEntry(ctx, entry); err != nil {
		return nil, fmt.Errorf("adding timeline entry: %w", err)
	}
	return entry, nil
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

	// ErrPendingActionNotFound is returned when a pending action ID does not
	// exist, or exists under a different incident than the one requested.
	ErrPendingActionNotFound = errors.New("pending action not found")

	// ErrAlreadyDecided is returned when ApproveAction/RejectAction is called
	// on a pending action that has already been approved, rejected, refused,
	// or blocked.
	ErrAlreadyDecided = errors.New("pending action already decided")

	// ErrSelfApproval is returned when the authenticated caller of
	// ApproveAction/RejectAction is the same identity as the Operator who
	// proposed the action — the cryptographic core of Separation of Duties.
	ErrSelfApproval = errors.New("verifier must be a different authenticated user than the operator")
)
