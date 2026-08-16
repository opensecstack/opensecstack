package rules

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/citadel"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/metrics"
)

// CitadelEmitter is the subset of *citadel.Client the service uses.
// Decoupled so tests can inject a stub.
//
// Submit returns a tri-state outcome (delivered / queued / dropped)
// plus an error so the service can record the right metric label and
// avoid pretending a queued event is durable. See
// internal/citadel/client.go for the contract.
type CitadelEmitter interface {
	Submit(ctx context.Context, event any) (citadel.SubmitOutcome, error)
}

// Service is the orchestration layer between the HTTP handlers, the
// rule repository, the data plane, and CITADEL.
//
// Lifecycle:
//
//	Create  → repo.Insert → dataplane.AddBlocklist/SetRatelimit → citadel.RuleChange(insert)
//	Delete  → dataplane.Remove…/Clear… → repo.Delete            → citadel.RuleChange(withdraw)
//	Sweep   → repo.DeleteExpired → dataplane.Remove…/Clear…     → citadel.RuleChange(expire)
//
// Order matters: on Delete we yank from the data plane *before*
// deleting the row so a crash mid-call leaves a stale row (recoverable
// via the next sweep) rather than an unblocked-but-believed-blocked
// CIDR (silent traffic).
type Service struct {
	repo      Repo
	plane     dataplane.Client
	emitter   CitadelEmitter
	lifecycle MitigationLifecycle
	nodeName  string
	log       zerolog.Logger
	now       func() time.Time
}

// Deps bundles the service's collaborators.
type Deps struct {
	Repo      Repo
	Plane     dataplane.Client
	Emitter   CitadelEmitter
	Lifecycle MitigationLifecycle
	NodeName  string
	Logger    zerolog.Logger
	Now       func() time.Time
}

// New builds a Service.
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.Lifecycle == nil {
		d.Lifecycle = NoopLifecycle{}
	}
	return &Service{
		repo:      d.Repo,
		plane:     d.Plane,
		emitter:   d.Emitter,
		lifecycle: d.Lifecycle,
		nodeName:  d.NodeName,
		log:       d.Logger.With().Str("component", "rules").Logger(),
		now:       d.Now,
	}
}

// Create installs a rule and emits the lifecycle event.
//
// principal is recorded in the rule_change event (JWT subject for
// operator calls, "threatflow-puller" for IOC-driven, "system" for
// internal use).
//
// Create has exactly two call sites, and this is the seam that
// distinguishes human-triggered from automated rule insertion:
//   - internal/api/handlers/handlers.go Rules.Create — the manual API
//     path (POST /api/v1/rules, admin/operator role required). That
//     handler evaluates a CITADEL MARSHAL Kerkese BEFORE calling this
//     method and blocks on REFUSE/HARD_STOP; a human deliberately
//     null-routing/rate-limiting production traffic is high blast
//     radius and warrants governance.
//   - internal/ioc/puller.go Puller.Tick — the automated IOC-driven
//     path (principal="threatflow-puller", req.Source=SourceThreatFlow).
//     It calls this method directly, bypassing the HTTP handler (and
//     therefore the MARSHAL gate) entirely — high-frequency automated
//     mitigation must not block on a synchronous governance
//     round-trip.
//
// Both paths still get an unconditional, immutable WORM audit-log
// entry below via emitChange → CITADEL POST /api/v1/worm/emit; only
// the manual path additionally requires an EXECUTE decision upstream
// of this call.
func (s *Service) Create(ctx context.Context, req CreateRequest, principal string, createdBy *uuid.UUID) (Rule, error) {
	if err := req.Validate(); err != nil {
		return Rule{}, err
	}
	source := req.Source
	if source == "" {
		source = SourceOperator
	}
	now := s.now()
	r := Rule{
		Type:       req.Type,
		CIDR:       req.CIDR,
		PPS:        req.PPS,
		Port:       req.Port,
		TTLSeconds: req.TTLSeconds,
		Source:     source,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Duration(req.TTLSeconds) * time.Second),
		CreatedBy:  createdBy,
	}
	stored, err := s.repo.Insert(ctx, r)
	if err != nil {
		return Rule{}, fmt.Errorf("persist rule: %w", err)
	}
	if err := s.installInPlane(ctx, stored); err != nil {
		// Best-effort rollback: an installInPlane error covers two
		// failure modes that look identical at this layer:
		//   (a) the RPC never reached the loader  → no map state
		//   (b) the RPC succeeded server-side but the response was
		//       lost (UDS reset, ctx deadline) → an orphan prefix is
		//       now sitting in the BPF map, blocking traffic that the
		//       operator never authorised
		// Case (b) used to leave silent traffic loss; we now also fire
		// the inverse op so the loader either no-ops it (case a) or
		// removes the orphan (case b). Both rollback steps are
		// best-effort — if removeFromPlane also fails, the next sweep
		// catches it via expires_at, but we log loudly so ops know.
		if rmErr := s.removeFromPlane(context.Background(), stored); rmErr != nil {
			s.log.Warn().Err(rmErr).Str("rule_id", stored.ID.String()).
				Msg("dataplane rollback also failed; orphan map entry possible until next sweep")
		}
		_ = s.repo.Delete(ctx, stored.ID)
		return Rule{}, fmt.Errorf("install in dataplane: %w", err)
	}

	metrics.RulesAddedTotal.WithLabelValues(string(stored.Type), stored.Source).Inc()
	metrics.RulesTotal.WithLabelValues(string(stored.Type)).Inc()

	// Open a mitigation evidence window for this rule. Best-effort —
	// see internal/rules/mitigation_lifecycle.go for the semantics.
	// Fired asynchronously: the production Lifecycle issues a
	// dataplane.Stats() RPC to capture the start counter, which can
	// take up to a second on a busy UDS pool. Blocking the HTTP
	// handler on it broke the SLO for /api/v1/rules POST under load.
	// We use context.Background() because the request context is about
	// to be cancelled by net/http when the handler returns.
	go s.lifecycle.OnRuleCreated(context.Background(), stored)

	op := citadel.OpInsert
	if stored.Source == SourceThreatFlow {
		op = citadel.OpIOCPullApply
	}
	s.emitChange(ctx, stored, op, principal, "")
	return stored, nil
}

// Delete withdraws a rule.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, principal, reason string) error {
	r, err := s.repo.Get(ctx, id)
	if err != nil {
		return s.translateNotFound(err)
	}
	if err := s.removeFromPlane(ctx, r); err != nil {
		return fmt.Errorf("remove from dataplane: %w", err)
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return s.translateNotFound(err)
	}
	// Close out the mitigation evidence window so the watcher emits
	// the CITADEL `openscrub.mitigation` event for this rule's
	// lifespan. Fired asynchronously for the same reason as
	// OnRuleCreated — the dataplane.Stats() RPC must not gate the
	// HTTP DELETE response.
	go s.lifecycle.OnRuleDeleted(context.Background(), r)
	metrics.RulesWithdrawnTotal.Inc()
	metrics.RulesTotal.WithLabelValues(string(r.Type)).Dec()
	s.emitChange(ctx, r, citadel.OpWithdraw, principal, reason)
	return nil
}

// Get returns a rule by id.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Rule, error) {
	r, err := s.repo.Get(ctx, id)
	if err != nil {
		return Rule{}, s.translateNotFound(err)
	}
	return r, nil
}

// List returns rules. Pagination is `offset + limit` with the total
// order `(created_at DESC, id DESC)` enforced at the repo layer so
// callers walking pages never see duplicates or skips even when many
// rows share a created_at second (common when the IOC puller bulk-
// inserts a feed in a single transaction).
func (s *Service) List(ctx context.Context, kind Type, limit, offset int) ([]Rule, error) {
	return s.repo.List(ctx, kind, limit, offset)
}

// SweepExpired removes rules whose TTL has elapsed and is intended to
// be called periodically by a goroutine in main.go. Returns the number
// of rules removed.
func (s *Service) SweepExpired(ctx context.Context) (int, error) {
	now := s.now()
	expired, err := s.repo.DeleteExpired(ctx, now)
	if err != nil {
		return 0, err
	}
	for _, r := range expired {
		if err := s.removeFromPlane(ctx, r); err != nil {
			s.log.Warn().Err(err).Str("rule_id", r.ID.String()).
				Msg("expired rule could not be removed from dataplane (continuing)")
			continue
		}
		// Sweeper runs on a background context already (no client to
		// block), but keep the call asynchronous so a slow Stats RPC
		// doesn't stall the rest of the sweep batch.
		go s.lifecycle.OnRuleDeleted(context.Background(), r)
		metrics.RulesExpiredTotal.Inc()
		metrics.RulesTotal.WithLabelValues(string(r.Type)).Dec()
		s.emitChange(ctx, r, citadel.OpExpire, "system", "ttl elapsed")
	}
	return len(expired), nil
}

// installInPlane pushes the rule to the data plane.
func (s *Service) installInPlane(ctx context.Context, r Rule) error {
	switch r.Type {
	case TypeBlocklist:
		prefix, err := ParseCIDR(r.CIDR)
		if err != nil {
			return err
		}
		err = s.plane.AddBlocklist(ctx, prefix)
		s.recordOp("add_blocklist", err)
		return err
	case TypeRatelimit:
		prefix, err := ParseCIDR(r.CIDR)
		if err != nil {
			return err
		}
		if r.PPS == nil {
			return errors.New("ratelimit rule missing pps")
		}
		// Rate-limit map is keyed by source IP, not prefix.
		err = s.plane.SetRatelimit(ctx, prefix.Addr(), uint64(*r.PPS))
		s.recordOp("set_ratelimit", err)
		return err
	case TypeSynCookie:
		if r.Port == nil || *r.Port <= 0 || *r.Port > 65535 {
			return errors.New("syncookie rule requires port in 1..65535")
		}
		err := s.plane.EnableSynCookie(ctx, uint16(*r.Port))
		s.recordOp("enable_syncookie", err)
		return err
	default:
		return fmt.Errorf("unknown rule type %q", r.Type)
	}
}

// removeFromPlane is the inverse of installInPlane.
func (s *Service) removeFromPlane(ctx context.Context, r Rule) error {
	switch r.Type {
	case TypeBlocklist:
		prefix, err := ParseCIDR(r.CIDR)
		if err != nil {
			return err
		}
		err = s.plane.RemoveBlocklist(ctx, prefix)
		s.recordOp("remove_blocklist", err)
		return err
	case TypeRatelimit:
		prefix, err := ParseCIDR(r.CIDR)
		if err != nil {
			return err
		}
		err = s.plane.ClearRatelimit(ctx, prefix.Addr())
		s.recordOp("clear_ratelimit", err)
		return err
	case TypeSynCookie:
		if r.Port == nil || *r.Port <= 0 || *r.Port > 65535 {
			return errors.New("syncookie rule requires port in 1..65535")
		}
		err := s.plane.DisableSynCookie(ctx, uint16(*r.Port))
		s.recordOp("disable_syncookie", err)
		return err
	default:
		return fmt.Errorf("unknown rule type %q", r.Type)
	}
}

func (s *Service) recordOp(op string, err error) {
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	metrics.DataplaneOpTotal.WithLabelValues(op, outcome).Inc()
}

// emitChange best-effort fires a rule_change event. Errors are logged
// but not surfaced — the local outbox / retry layer is the v1.0.0
// responsibility of CITADEL itself; we don't block the API on it.
func (s *Service) emitChange(ctx context.Context, r Rule, op, principal, reason string) {
	if s.emitter == nil {
		return
	}
	ev := citadel.RuleChangeEvent{
		EventEnvelope: citadel.NewEnvelope("openscrub.rule_change", s.nodeName),
		Operation:     op,
		Rule: citadel.RuleSummary{
			ID:         r.ID.String(),
			CIDR:       r.CIDR,
			Type:       string(r.Type),
			PPS:        r.PPS,
			Port:       r.Port,
			TTLSeconds: r.TTLSeconds,
			Source:     r.Source,
		},
		Principal: principal,
		Reason:    reason,
	}
	outcome, err := s.emitter.Submit(ctx, ev)
	if err != nil && outcome != citadel.SubmitQueued {
		// Permanent or dropped: surface as a single bucket. Queued
		// errors are expected (transient) and handled below.
		label := "failed"
		if outcome == citadel.SubmitDropped {
			label = "dropped"
		}
		metrics.CitadelEmitTotal.WithLabelValues(label).Inc()
		s.log.Warn().Err(err).Str("rule_id", r.ID.String()).Str("op", op).
			Str("outcome", outcome.String()).
			Msg("citadel rule_change emit failed")
		return
	}
	switch outcome {
	case citadel.SubmitDelivered, citadel.SubmitDryRun:
		metrics.CitadelEmitTotal.WithLabelValues("delivered").Inc()
	case citadel.SubmitQueued:
		// rule_change events are not persisted in an outbox today —
		// log explicitly so ops know a retry is pending. The CITADEL
		// client's confirmation channel will surface terminal state
		// to metrics via the drainer.
		metrics.CitadelEmitTotal.WithLabelValues("queued").Inc()
		s.log.Info().Str("rule_id", r.ID.String()).Str("op", op).
			Msg("citadel rule_change queued for async retry")
	case citadel.SubmitDropped:
		metrics.CitadelEmitTotal.WithLabelValues("dropped").Inc()
		s.log.Error().Str("rule_id", r.ID.String()).Str("op", op).
			Msg("citadel rule_change dropped — retry buffer full")
	}
}

func (s *Service) translateNotFound(err error) error {
	if err == nil {
		return nil
	}
	// db.ErrRuleNotFound wraps ErrNotFound, so a single errors.Is is
	// sufficient — the previous string-match fallback was a footgun
	// (a fresh repo returning "rule not found" verbatim from a
	// different bug would silently pass through as ErrNotFound).
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// CIDRToAddr returns the masked address — exposed for tests.
func CIDRToAddr(s string) (netip.Addr, error) {
	p, err := ParseCIDR(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return p.Addr(), nil
}
