package advisory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/citadel"
	"github.com/opensecstack/opencsirt/internal/db"
	"github.com/opensecstack/opencsirt/internal/integrations"
)

var (
	ErrInvalidTLP       = errors.New("advisory: invalid TLP (clear|green|amber|red)")
	ErrEmptyTitle       = errors.New("advisory: title is required")
	ErrAlreadyPublished = errors.New("advisory: already published")
)

type Service struct {
	store      *db.AdvisoryStore
	outbox     *db.OutboxStore
	audit      *db.AuditStore
	python     PythonClient
	ThreatFlow *integrations.ThreatFlowClient
	log        zerolog.Logger
}

func NewService(store *db.AdvisoryStore, outbox *db.OutboxStore, audit *db.AuditStore, python PythonClient) *Service {
	return &Service{store: store, outbox: outbox, audit: audit, python: python, log: zerolog.Nop()}
}

type CreateInput struct {
	IncidentID *uuid.UUID
	Title      string
	Summary    string
	TLP        string
	IOCs       []IOC
	Vuln       map[string]any
}

func (s *Service) Create(ctx context.Context, in CreateInput, actor uuid.UUID, role string) (*db.Advisory, error) {
	if strings.TrimSpace(in.Title) == "" {
		return nil, ErrEmptyTitle
	}
	// M2: normalize TLP to lowercase before validation and persistence.
	in.TLP = strings.ToLower(in.TLP)
	if !validTLP(in.TLP) {
		return nil, ErrInvalidTLP
	}

	req := GenerateRequest{
		Title:         in.Title,
		Summary:       in.Summary,
		TLP:           in.TLP,
		IOCs:          in.IOCs,
		Vulnerability: in.Vuln,
	}
	if in.IncidentID != nil {
		req.IncidentID = in.IncidentID.String()
	}
	resp, err := s.python.Generate(ctx, req)
	if err != nil {
		return nil, err
	}

	a := &db.Advisory{
		IncidentID: in.IncidentID,
		CSAFID:     resp.CSAFID,
		CSAFDoc:    resp.Doc,
		State:      "draft",
		TLP:        in.TLP,
		Title:      in.Title,
		Summary:    in.Summary,
	}
	if err := s.store.Insert(ctx, a); err != nil {
		return nil, err
	}
	if err := s.audit.Insert(ctx, &db.AuditEntry{
		ActorID: &actor, ActorRole: role, Action: "advisory.create",
		TargetType: "advisory", TargetID: &a.ID,
		Metadata: map[string]any{"csaf_id": a.CSAFID, "tlp": a.TLP},
	}); err != nil {
		s.log.Error().Err(err).Msg("audit insert failed")
	}
	return a, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID, actor uuid.UUID, role string) (*db.Advisory, error) {
	a, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.audit.Insert(ctx, &db.AuditEntry{
		ActorID: &actor, ActorRole: role, Action: "advisory.read",
		TargetType: "advisory", TargetID: &id,
	}); err != nil {
		s.log.Error().Err(err).Msg("audit insert failed")
	}
	return a, nil
}

func (s *Service) List(ctx context.Context, f db.AdvisoryFilter, actor uuid.UUID, role string) ([]*db.Advisory, int, error) {
	items, total, err := s.store.List(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	if err := s.audit.Insert(ctx, &db.AuditEntry{
		ActorID: &actor, ActorRole: role, Action: "advisory.list",
		TargetType: "advisory",
	}); err != nil {
		s.log.Error().Err(err).Msg("audit insert failed")
	}
	return items, total, nil
}

func (s *Service) Publish(ctx context.Context, id, actor uuid.UUID, role string) (*db.Advisory, error) {
	if err := s.store.Publish(ctx, id, actor); err != nil {
		return nil, err
	}
	a, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// L4: verify advisory reached expected state after store.Publish.
	if a.State == "draft" {
		// store.Publish succeeded but state did not advance — skip outbox.
		s.log.Error().Str("advisory_id", id.String()).Msg("advisory still in draft after Publish call; skipping outbox enqueue")
		return a, nil
	}
	if a.State != "published" {
		return nil, fmt.Errorf("advisory in unexpected state %q after publish", a.State)
	}

	var publishedAtStr string
	if a.PublishedAt != nil {
		publishedAtStr = a.PublishedAt.UTC().Format(time.RFC3339)
	}
	pubEntry := &db.OutboxEntry{
		EventType: citadel.EventAdvisoryPublished,
		EventID:   "advisory-publish-" + id.String(),
		Payload: map[string]any{
			"advisory_id":  id.String(),
			"csaf_id":      a.CSAFID,
			"tlp":          a.TLP,
			"published_at": publishedAtStr,
			"incident_id":  a.IncidentID,
		},
		TargetType: "advisory",
		TargetID:   &id,
	}
	if err := s.outbox.Enqueue(ctx, pubEntry); err != nil {
		s.log.Error().Err(err).Str("event_type", pubEntry.EventType).Msg("outbox enqueue failed")
	}

	if err := s.audit.Insert(ctx, &db.AuditEntry{
		ActorID: &actor, ActorRole: role, Action: "advisory.publish",
		TargetType: "advisory", TargetID: &id,
	}); err != nil {
		s.log.Error().Err(err).Msg("audit insert failed")
	}

	if s.ThreatFlow != nil {
		published := a
		go func() {
			ctx2, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := s.ThreatFlow.PushAdvisory(ctx2, published.CSAFDoc); err != nil {
				s.log.Warn().Err(err).Str("advisory_id", published.ID.String()).Msg("threatflow push failed")
			}
		}()
	}

	return a, nil
}

func (s *Service) Withdraw(ctx context.Context, id, actor uuid.UUID, role string) (*db.Advisory, error) {
	if err := s.store.Withdraw(ctx, id); err != nil {
		return nil, err
	}
	a, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.audit.Insert(ctx, &db.AuditEntry{
		ActorID: &actor, ActorRole: role, Action: "advisory.withdraw",
		TargetType: "advisory", TargetID: &id,
	}); err != nil {
		s.log.Error().Err(err).Msg("audit insert failed")
	}
	return a, nil
}

func validTLP(t string) bool {
	switch t {
	case "clear", "green", "amber", "red":
		return true
	}
	return false
}
