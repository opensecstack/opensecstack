package ioc

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/metrics"
)

// SourceSpec couples a Source with its tick interval. Operators can
// run the same adapter type twice (e.g. two MISP feeds) by registering
// distinct names.
type SourceSpec struct {
	Source   Source
	Interval time.Duration
}

// Puller schedules periodic fetches across N sources, applies the
// allowlist, upserts surviving IOCs, and emits one CITADEL evidence
// record per successful pull.
type Puller struct {
	store     *Store
	sources   []SourceSpec
	allow     *Allowlist
	met       metrics.IOCMetrics
	logger    zerolog.Logger
	citadel   citadelEmitter
	tenant    string
	sweepEvery time.Duration
}

// citadelEmitter mirrors the handlers.WORMEmitter shape so the puller
// stays decoupled from the API package.
type citadelEmitter interface {
	EmitAsync(ctx context.Context, ev citadel.Evidence) bool
}

// PullerConfig bundles construction parameters.
type PullerConfig struct {
	Store         *Store
	Sources       []SourceSpec
	Allow         *Allowlist
	Metrics       metrics.IOCMetrics
	Logger        zerolog.Logger
	Citadel       citadelEmitter
	Tenant        string
	SweepInterval time.Duration
}

// New constructs a Puller. A nil Metrics is replaced with a no-op so
// the hot-path never branch-checks.
func New(cfg PullerConfig) *Puller {
	if cfg.Metrics == nil {
		cfg.Metrics = metrics.NopIOCMetrics{}
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = 1 * time.Hour
	}
	return &Puller{
		store:      cfg.Store,
		sources:    cfg.Sources,
		allow:      cfg.Allow,
		met:        cfg.Metrics,
		logger:     cfg.Logger.With().Str("component", "ioc-puller").Logger(),
		citadel:    cfg.Citadel,
		tenant:     cfg.Tenant,
		sweepEvery: cfg.SweepInterval,
	}
}

// Run schedules every source on its own ticker and the expiry sweep on
// a separate goroutine. Returns when ctx is cancelled and every
// goroutine has exited.
func (p *Puller) Run(ctx context.Context) {
	if p.store == nil || len(p.sources) == 0 {
		p.logger.Info().Msg("puller idle: no store or no sources configured")
		<-ctx.Done()
		return
	}
	var wg sync.WaitGroup
	for _, s := range p.sources {
		s := s
		if s.Interval <= 0 {
			s.Interval = 1 * time.Hour
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.runSource(ctx, s)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.runSweep(ctx)
	}()
	wg.Wait()
}

func (p *Puller) runSource(ctx context.Context, s SourceSpec) {
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	// Fire immediately so a fresh deploy doesn't wait a full interval
	// for the first pull.
	if err := p.Tick(ctx, s.Source); err != nil {
		p.logger.Warn().Str("source", s.Source.Name()).Err(err).
			Msg("initial pull failed")
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.Tick(ctx, s.Source); err != nil {
				p.logger.Warn().Str("source", s.Source.Name()).Err(err).
					Msg("pull failed")
			}
		}
	}
}

func (p *Puller) runSweep(ctx context.Context) {
	t := time.NewTicker(p.sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			deleted, err := p.store.ExpireSweep(ctx)
			if err != nil {
				p.logger.Warn().Err(err).Msg("expire sweep failed")
				continue
			}
			active, err := p.store.CountActive(ctx)
			if err == nil {
				p.met.SetActive(float64(active))
			}
			if deleted > 0 {
				p.logger.Info().Int64("deleted", deleted).Int64("active", active).
					Msg("ioc sweep complete")
			}
		}
	}
}

// Tick performs one pull from a single source. Public so tests can
// drive it without spinning up the scheduler.
func (p *Puller) Tick(ctx context.Context, src Source) error {
	name := src.Name()
	started := time.Now().UTC()
	audit := PullAudit{Source: name, StartedAt: started}

	items, err := src.Fetch(ctx)
	if err != nil {
		audit.FinishedAt = time.Now().UTC()
		audit.Error = err.Error()
		p.met.IncFailure(name)
		p.met.IncPull(name, "fail")
		_ = p.store.AuditInsert(ctx, audit)
		return err
	}
	audit.Fetched = len(items)

	for _, it := range items {
		if !ValidKind(it.Kind) || it.Value == "" {
			audit.Skipped++
			continue
		}
		if p.allow != nil && p.allow.Matches(it.Kind, it.Value) {
			audit.Skipped++
			continue
		}
		if it.Tenant == "" {
			it.Tenant = p.tenant
		}
		res, err := p.store.Upsert(ctx, it)
		if err != nil {
			audit.Skipped++
			p.logger.Debug().Err(err).Str("value", it.Value).Msg("upsert failed")
			continue
		}
		switch res {
		case UpsertInserted:
			audit.Inserted++
		case UpsertUpdated:
			audit.Updated++
		}
	}
	audit.FinishedAt = time.Now().UTC()

	if err := p.store.AuditInsert(ctx, audit); err != nil {
		p.logger.Warn().Err(err).Msg("audit insert failed")
	}

	p.met.IncPull(name, "ok")
	p.emitSync(ctx, audit)
	p.logger.Info().
		Str("source", name).
		Int("fetched", audit.Fetched).
		Int("inserted", audit.Inserted).
		Int("updated", audit.Updated).
		Int("skipped", audit.Skipped).
		Msg("ioc pull complete")
	return nil
}

func (p *Puller) emitSync(ctx context.Context, a PullAudit) {
	if p.citadel == nil {
		return
	}
	p.citadel.EmitAsync(ctx, citadel.Evidence{
		EventType: "vertguard.threatfeed.sync_complete",
		Subject:   "threatfeed/" + a.Source,
		Verdict:   "informational",
		Tenant:    p.tenant,
		Timestamp: a.FinishedAt,
	})
}
