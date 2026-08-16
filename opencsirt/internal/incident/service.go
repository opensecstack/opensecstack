// Package incident owns the CSIRT-side incident lifecycle:
// open → triaged → contained → closed. Every state transition emits a
// CITADEL event via the outbox.
package incident

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/citadel"
	"github.com/opensecstack/opencsirt/internal/db"
)

var (
	ErrInvalidSource   = errors.New("incident: invalid source")
	ErrInvalidSeverity = errors.New("incident: invalid severity")
	ErrInvalidStatus   = errors.New("incident: invalid status")
	ErrEmptyTitle      = errors.New("incident: title is required")
	ErrAlreadyClosed   = errors.New("incident: already closed")
)

var (
	validSources    = map[string]bool{"irflow": true, "manual": true, "abuse_mailbox": true, "peer_csirt": true}
	validSeverities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	validStatuses   = map[string]bool{"open": true, "triaged": true, "contained": true, "closed": true}
)

// incidentStore, outboxStore and auditStore are the persistence seams
// Service depends on. The real implementations are *db.IncidentStore,
// *db.OutboxStore and *db.AuditStore; tests substitute fakes to exercise
// success and partial-failure branches deterministically without a live
// Postgres.
type incidentStore interface {
	Insert(ctx context.Context, i *db.Incident) error
	Get(ctx context.Context, id uuid.UUID) (*db.Incident, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string, closedAt *time.Time) error
	List(ctx context.Context, f db.IncidentFilter) ([]*db.Incident, int, error)
}

type outboxStore interface {
	Enqueue(ctx context.Context, e *db.OutboxEntry) error
}

type auditStore interface {
	Insert(ctx context.Context, a *db.AuditEntry) error
}

type Service struct {
	incidents incidentStore
	outbox    outboxStore
	audit     auditStore
	logger    zerolog.Logger
}

// New wires a Service against the concrete DB-backed stores. Kept typed as
// *db.IncidentStore / *db.OutboxStore / *db.AuditStore (rather than the
// narrower interfaces above) so call sites are unaffected; all three types
// implicitly satisfy incidentStore/outboxStore/auditStore.
func New(i *db.IncidentStore, o *db.OutboxStore, a *db.AuditStore, logger zerolog.Logger) *Service {
	return &Service{incidents: i, outbox: o, audit: a, logger: logger}
}

type CreateInput struct {
	ConstituencyID *uuid.UUID
	Source         string
	Severity       string
	Title          string
	Description    string
	Metadata       map[string]any
}

func (s *Service) Create(ctx context.Context, in CreateInput, actor uuid.UUID, role string) (*db.Incident, error) {
	if !validSources[in.Source] {
		return nil, ErrInvalidSource
	}
	if !validSeverities[in.Severity] {
		return nil, ErrInvalidSeverity
	}
	if strings.TrimSpace(in.Title) == "" {
		return nil, ErrEmptyTitle
	}
	inc := &db.Incident{
		ConstituencyID: in.ConstituencyID,
		Source:         in.Source,
		Severity:       in.Severity,
		Status:         "open",
		Title:          strings.TrimSpace(in.Title),
		Description:    in.Description,
		Metadata:       in.Metadata,
	}
	if err := s.incidents.Insert(ctx, inc); err != nil {
		return nil, err
	}

	// Enqueue CITADEL event.
	entry := &db.OutboxEntry{
		EventType: citadel.EventIncidentOpened,
		EventID:   "incident-open-" + inc.ID.String(),
		Payload: map[string]any{
			"incident_id":     inc.ID.String(),
			"constituency_id": inc.ConstituencyID,
			"severity":        inc.Severity,
			"source":          inc.Source,
			"opened_at":       inc.OpenedAt,
		},
		TargetType: "incident",
		TargetID:   &inc.ID,
	}
	if err := s.outbox.Enqueue(ctx, entry); err != nil {
		s.logger.Error().Err(err).Str("event_type", entry.EventType).Msg("outbox enqueue failed")
	}

	if err := s.audit.Insert(ctx, &db.AuditEntry{
		ActorID: &actor, ActorRole: role, Action: "incident.create",
		TargetType: "incident", TargetID: &inc.ID,
		Metadata: map[string]any{"severity": inc.Severity, "source": inc.Source},
	}); err != nil {
		s.logger.Error().Err(err).Msg("audit insert failed")
	}
	return inc, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*db.Incident, error) {
	return s.incidents.Get(ctx, id)
}

func (s *Service) List(ctx context.Context, f db.IncidentFilter) ([]*db.Incident, int, error) {
	return s.incidents.List(ctx, f)
}

func (s *Service) Close(ctx context.Context, id uuid.UUID, actor uuid.UUID, role string) (*db.Incident, error) {
	inc, err := s.incidents.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if inc.Status == "closed" {
		return nil, ErrAlreadyClosed
	}
	now := time.Now().UTC()
	if err := s.incidents.UpdateStatus(ctx, id, "closed", &now); err != nil {
		return nil, err
	}
	inc.Status = "closed"
	inc.ClosedAt = &now

	closeEntry := &db.OutboxEntry{
		EventType: citadel.EventIncidentClosed,
		EventID:   "incident-close-" + id.String(),
		Payload: map[string]any{
			"incident_id": id.String(),
			"closed_at":   now,
			"closed_by":   actor.String(),
		},
		TargetType: "incident",
		TargetID:   &id,
	}
	if err := s.outbox.Enqueue(ctx, closeEntry); err != nil {
		s.logger.Error().Err(err).Str("event_type", closeEntry.EventType).Msg("outbox enqueue failed")
	}
	if err := s.audit.Insert(ctx, &db.AuditEntry{
		ActorID: &actor, ActorRole: role, Action: "incident.close",
		TargetType: "incident", TargetID: &id,
	}); err != nil {
		s.logger.Error().Err(err).Msg("audit insert failed")
	}
	return inc, nil
}

func (s *Service) UpdateStatus(ctx context.Context, id uuid.UUID, status string, actor uuid.UUID, role string) error {
	if !validStatuses[status] {
		return ErrInvalidStatus
	}

	// H3: idempotency guard — fetch current state and return early if already at target.
	existing, err := s.incidents.Get(ctx, id)
	if err != nil {
		return err
	}
	if existing.Status == status {
		return nil // already in target state, idempotent
	}

	if err := s.incidents.UpdateStatus(ctx, id, status, nil); err != nil {
		return err
	}

	if status == "triaged" {
		escalateEntry := &db.OutboxEntry{
			EventType: citadel.EventEscalationSent,
			EventID:   "incident-escalate-" + id.String(),
			Payload: map[string]any{
				"incident_id":  id.String(),
				"escalated_by": actor.String(),
				"status":       status,
			},
			TargetType: "incident",
			TargetID:   &id,
		}
		if err := s.outbox.Enqueue(ctx, escalateEntry); err != nil {
			s.logger.Error().Err(err).Str("event_type", escalateEntry.EventType).Msg("outbox enqueue failed")
		}
	}

	if err := s.audit.Insert(ctx, &db.AuditEntry{
		ActorID: &actor, ActorRole: role, Action: "incident.update_status",
		TargetType: "incident", TargetID: &id,
		Metadata: map[string]any{"status": status},
	}); err != nil {
		s.logger.Error().Err(err).Msg("audit insert failed")
	}
	return nil
}
