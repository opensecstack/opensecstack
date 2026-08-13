// Package constituency owns the CSIRT constituency lifecycle:
// onboarding, contact updates, NIS2 status tracking.
package constituency

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/db"
)

var (
	ErrInvalidNIS2Status = errors.New("constituency: invalid nis2_status (essential|important|out_of_scope)")
	ErrInvalidTLP        = errors.New("constituency: invalid tlp_default (clear|green|amber|red)")
	ErrInvalidEmail      = errors.New("constituency: invalid email")
	ErrEmptyField        = errors.New("constituency: name and sector are required")
)

// constituencyStore is the persistence seam Service depends on. The real
// implementation is *db.ConstituencyStore; tests substitute a fake to
// exercise success and partial-failure branches deterministically without
// a live Postgres.
type constituencyStore interface {
	Insert(ctx context.Context, c *db.Constituency) error
	Get(ctx context.Context, id uuid.UUID) (*db.Constituency, error)
	Update(ctx context.Context, c *db.Constituency) error
	List(ctx context.Context, limit, offset int) ([]*db.Constituency, int, error)
}

// auditStore is the persistence seam for audit-trail writes.
type auditStore interface {
	Insert(ctx context.Context, a *db.AuditEntry) error
}

type Service struct {
	store  constituencyStore
	audit  auditStore
	logger zerolog.Logger
}

// New wires a Service against the concrete DB-backed stores. Kept typed as
// *db.ConstituencyStore / *db.AuditStore (rather than the narrower
// interfaces above) so call sites are unaffected; both types implicitly
// satisfy constituencyStore/auditStore.
func New(store *db.ConstituencyStore, audit *db.AuditStore, logger zerolog.Logger) *Service {
	return &Service{store: store, audit: audit, logger: logger}
}

type CreateInput struct {
	Name                  string
	Sector                string
	Country               string
	NIS2Status            string
	TLPDefault            string // clear|green|amber|red; defaults to "green"
	PrimaryContactEmail   string
	SecondaryContactEmail string
}

func (s *Service) Create(ctx context.Context, in CreateInput, actor uuid.UUID, role string) (*db.Constituency, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	tlp := in.TLPDefault
	if tlp == "" {
		tlp = "green"
	}
	c := &db.Constituency{
		Name:                  strings.TrimSpace(in.Name),
		Sector:                strings.TrimSpace(in.Sector),
		Country:               strings.ToUpper(strings.TrimSpace(in.Country)),
		NIS2Status:            in.NIS2Status,
		TLPDefault:            tlp,
		PrimaryContactEmail:   strings.TrimSpace(in.PrimaryContactEmail),
		SecondaryContactEmail: optional(in.SecondaryContactEmail),
	}
	if err := s.store.Insert(ctx, c); err != nil {
		return nil, err
	}
	if err := s.audit.Insert(ctx, &db.AuditEntry{
		ActorID: &actor, ActorRole: role, Action: "constituency.create",
		TargetType: "constituency", TargetID: &c.ID,
		Metadata: map[string]any{"name": c.Name, "country": c.Country},
	}); err != nil {
		s.logger.Error().Err(err).Msg("audit insert failed")
	}
	return c, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*db.Constituency, error) {
	return s.store.Get(ctx, id)
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, in CreateInput, actor uuid.UUID, role string) (*db.Constituency, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	c, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	tlp := in.TLPDefault
	if tlp == "" {
		tlp = "green"
	}
	c.Name = strings.TrimSpace(in.Name)
	c.Sector = strings.TrimSpace(in.Sector)
	c.Country = strings.ToUpper(strings.TrimSpace(in.Country))
	c.NIS2Status = in.NIS2Status
	c.TLPDefault = tlp
	c.PrimaryContactEmail = strings.TrimSpace(in.PrimaryContactEmail)
	c.SecondaryContactEmail = optional(in.SecondaryContactEmail)
	if err := s.store.Update(ctx, c); err != nil {
		return nil, err
	}
	if err := s.audit.Insert(ctx, &db.AuditEntry{
		ActorID: &actor, ActorRole: role, Action: "constituency.update",
		TargetType: "constituency", TargetID: &c.ID,
	}); err != nil {
		s.logger.Error().Err(err).Msg("audit insert failed")
	}
	return c, nil
}

func (s *Service) List(ctx context.Context, limit, offset int) ([]*db.Constituency, int, error) {
	return s.store.List(ctx, limit, offset)
}

func validate(in CreateInput) error {
	if strings.TrimSpace(in.Name) == "" || strings.TrimSpace(in.Sector) == "" {
		return ErrEmptyField
	}
	switch in.NIS2Status {
	case "essential", "important", "out_of_scope":
	default:
		return ErrInvalidNIS2Status
	}
	tlp := in.TLPDefault
	if tlp == "" {
		tlp = "green"
	}
	switch tlp {
	case "clear", "green", "amber", "red":
	default:
		return ErrInvalidTLP
	}
	// Email is optional — validate format only when provided.
	if in.PrimaryContactEmail != "" {
		if _, err := mail.ParseAddress(in.PrimaryContactEmail); err != nil {
			return ErrInvalidEmail
		}
	}
	if in.SecondaryContactEmail != "" {
		if _, err := mail.ParseAddress(in.SecondaryContactEmail); err != nil {
			return ErrInvalidEmail
		}
	}
	return nil
}

func optional(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}
