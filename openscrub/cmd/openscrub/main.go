// Command openscrub is the OpenScrub control-plane daemon.
//
// Wires:
//   - HTTP API on :8087 (rules CRUD, health, metrics)
//   - PostgreSQL persistence (rules, ioc_ingest_log, mitigations)
//     OR an in-memory repo when OPENSCRUB_DB_URL is empty (dev)
//   - Dataplane client (UDS to the Rust loader, or noop on hosts
//     without CAP_BPF / for tests)
//   - ThreatFlow IOC puller goroutine
//   - CITADEL evidence emitter goroutine (rule_change inline,
//     mitigation events scanned by Watcher)
//   - Periodic TTL sweeper goroutine
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	sdkcitadel "github.com/opensecstack/sdk/go/citadel"

	"github.com/opensecstack/openscrub/internal/api"
	"github.com/opensecstack/openscrub/internal/api/handlers"
	"github.com/opensecstack/openscrub/internal/auth"
	"github.com/opensecstack/openscrub/internal/citadel"
	"github.com/opensecstack/openscrub/internal/config"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/db"
	"github.com/opensecstack/openscrub/internal/ioc"
	"github.com/opensecstack/openscrub/internal/metrics"
	"github.com/opensecstack/openscrub/internal/rules"
	"github.com/opensecstack/openscrub/internal/version"
)

func main() {
	cfg := config.FromEnv()
	logger := zerolog.New(os.Stderr).With().Timestamp().Str("svc", "openscrub").Logger()
	logger.Info().Str("version", version.Version).Str("addr", cfg.HTTPAddr).Msg("openscrub starting")
	if err := cfg.Validate(); err != nil {
		// Fail loudly and abort; never degrade silently to an insecure
		// default in non-dev mode.
		logger.Fatal().Err(err).Msg("config validation failed")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Repo: Postgres if configured, otherwise in-memory.
	var (
		repo            rules.Repo
		dbHandle        *db.DB
		mitStore        *db.MitigationStore
		iocLogger       ioc.IOCLoggerCompat
		mitStoreAdapter citadel.MitigationStore
	)
	if cfg.DBURL != "" {
		h, err := db.New(ctx, cfg.DBURL, cfg.DBMaxConns)
		if err != nil {
			logger.Fatal().Err(err).Msg("connect db")
		}
		dbHandle = h
		defer dbHandle.Close()
		repo = db.NewRuleStore(h.Pool)
		mitStore = db.NewMitigationStore(h.Pool)
		mitStoreAdapter = newMitigationStoreAdapter(repo, mitStore)
		ingestLog := db.NewIOCIngestLogStore(h.Pool)
		iocLogger = func(ctx context.Context, source, sha string, count int) error {
			_, err := ingestLog.Insert(ctx, source, sha, count)
			return err
		}
	} else {
		logger.Warn().Msg("OPENSCRUB_DB_URL empty — using in-memory repo (dev only)")
		repo = rules.NewMemoryRepo()
	}

	// Dataplane.
	plane := buildDataplane(cfg, logger)
	defer func() {
		if err := plane.Close(); err != nil {
			logger.Warn().Err(err).Msg("dataplane client close failed")
		}
	}()

	// CITADEL.
	//
	// Secret precedence (matches citadel.Client.activeSigner):
	//   OPENSCRUB_CITADEL_HMAC_SECRETS  (rotation list, primary first)
	//                                    ↓ when set, wins
	//   OPENSCRUB_CITADEL_HMAC_SECRET   (legacy single key, fallback)
	//
	// We warn loudly when both are set so an operator who copy-pastes
	// from old docs notices the legacy key is being shadowed instead of
	// silently signing with the new rotation slot.
	if len(cfg.CitadelKeySecrets) > 0 && cfg.CitadelKeySecret != "" {
		logger.Warn().
			Int("rotation_slots", len(cfg.CitadelKeySecrets)).
			Msg("both OPENSCRUB_CITADEL_HMAC_SECRETS and OPENSCRUB_CITADEL_HMAC_SECRET set — " +
				"the rotation list takes precedence; unset the legacy single-key var to silence this")
	}
	citadelClient := citadel.New(citadel.Config{
		BaseURL:     cfg.CitadelURL,
		ProjectID:   cfg.CitadelProjectID,
		HMACSecret:  cfg.CitadelKeySecret,
		HMACSecrets: cfg.CitadelKeySecrets,
		KeyID:       cfg.CitadelKeyID,
		KeyIDs:      cfg.CitadelKeyIDs,
		NodeName:    cfg.NodeName,
		DryRun:      cfg.CitadelDryRun,
	}, logger)
	citadelClient.StartRetryLoop(ctx)

	// CITADEL MARSHAL governance client — separate from citadelClient
	// (which only does WORM audit-log appends). Only wired when
	// OPENSCRUB_CITADEL_API_URL is set; nil disables the governance gate
	// on manual rule insertion (see handlers.Rules.Create), matching the
	// WORM emitter's own fail-open posture when CITADEL isn't
	// configured.
	var governor handlers.CitadelGovernor
	if cfg.CitadelURL != "" {
		governor = sdkcitadel.NewClient(cfg.CitadelURL, nil)
	}

	// Mitigation lifecycle: opens a `mitigations` row on rule create,
	// finalizes it on rule delete / TTL sweep, so the CITADEL watcher
	// has rows to emit. Falls back to a no-op when the DB is not wired
	// (dev mode without a Postgres URL).
	var mitLifecycle rules.MitigationLifecycle = rules.NoopLifecycle{}
	if mitStore != nil {
		mitLifecycle = rules.NewLifecycle(rules.LifecycleDeps{
			Store:  &lifecycleStoreAdapter{store: mitStore},
			Plane:  plane,
			Logger: logger,
		})
	}

	// Rules service (the orchestration layer).
	ruleSvc := rules.New(rules.Deps{
		Repo:      repo,
		Plane:     plane,
		Emitter:   citadelClient,
		Lifecycle: mitLifecycle,
		NodeName:  cfg.NodeName,
		Logger:    logger,
	})

	// Catch up after restart: re-open mitigation rows for any rule that
	// is still active in the rules table but has no open evidence row.
	//
	// Recovery is best-effort and runs once at startup — it must not
	// fail server boot. The previous 5s deadline aborted recovery
	// mid-loop on any node with >5 active rules (each rule's
	// OnRuleCreated previously triggered its own 1s Stats RPC). The
	// lifecycle now reads Stats once upfront and the budget is lifted
	// to 30s so even a slow Postgres or a 100k-rule recovery completes.
	if dbHandle != nil {
		recoverCtx, recoverCancel := context.WithTimeout(ctx, 30*time.Second)
		// Page through the active rule set so the recovery is bounded by
		// neither the OFFSET cliff (Postgres degrades past ~50k offset
		// without an index) nor the IOC puller's dedup ceiling. Each page
		// lookup uses the stable (created_at DESC, id DESC) order so the
		// pages do not overlap or skip rows even if the IOC puller is
		// inserting concurrently.
		const pageSize = 5000
		var (
			active []rules.Rule
			offset int
			pages  int
		)
		for {
			page, err := repo.List(recoverCtx, "", pageSize, offset)
			if err != nil {
				logger.Error().Err(err).Int("offset", offset).
					Msg("mitigation recovery: list page failed; continuing with what we have")
				metrics.MitigationsRecoveryFailedTotal.Inc()
				break
			}
			active = append(active, page...)
			pages++
			if len(page) < pageSize {
				break
			}
			offset += pageSize
		}
		logger.Info().Int("rules", len(active)).Int("pages", pages).
			Msg("mitigation recovery: starting")
		mitLifecycle.RecoverActive(recoverCtx, active)
		recoverCancel()
	}

	// HTTP server.
	hs256 := auth.NewHS256Verifier(cfg.JWTSecrets, cfg.JWTIssuer)
	verifier := auth.NewDualVerifier(hs256, cfg.SinauthURL)
	devMode := cfg.DevMode || !hs256.HasSecrets()
	if devMode {
		logger.Warn().Msg("auth in dev mode — JWT not enforced (set OPENSCRUB_JWT_SECRET to enable)")
	}

	// Real liveness probe — issue a Stats() RPC with a 1s timeout. The
	// noop client always returns OK, but a UDS client whose loader has
	// died will fail here, so /health no longer lies.
	planeAttached := func() bool {
		if cfg.DataplaneTransport == "noop" {
			return false
		}
		probeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := plane.Stats(probeCtx)
		return err == nil
	}
	healthH := &handlers.Health{Plane: plane, DataplaneAttached: planeAttached}
	if dbHandle != nil {
		healthH.DB = dbHandle
	}
	rulesH := &handlers.Rules{
		Service:          ruleSvc,
		Logger:           logger,
		Citadel:          governor,
		CitadelProjectID: cfg.CitadelProjectID,
		CitadelDryRun:    cfg.CitadelDryRun,
	}
	var mitigationsH *handlers.Mitigations
	if mitStore != nil {
		mitigationsH = &handlers.Mitigations{
			Lister: newMitigationListAdapter(mitStore),
			Logger: logger,
		}
	} else {
		// Dev mode without DB: still expose the route so dashboards
		// don't 404; the handler returns an empty list when Lister is nil.
		mitigationsH = &handlers.Mitigations{Logger: logger}
	}
	// Snapshot endpoint. Best-effort wiring: the rules / IOC adapters
	// fall back to in-memory zero counts when the DB is not present
	// (dev mode), so the dashboard never 404s.
	snapshotH := &handlers.Snapshot{
		Plane:             plane,
		Rules:             newSnapshotRulesAdapter(repo),
		Citadel:           citadelClient,
		DataplaneAttached: planeAttached,
		Logger:            logger,
	}
	if dbHandle != nil {
		snapshotH.IOC = newSnapshotIOCAdapter(db.NewIOCIngestLogStore(dbHandle.Pool))
	}

	// /auth/login issuer. Always wire the handler — when no users
	// are seeded it self-disables with a 503 response so the
	// dashboard surfaces the misconfiguration instead of 404.
	creds := auth.NewCredentialStore(cfg.PasswordPepper, cfg.UsersSpec)
	primarySecret := ""
	if len(cfg.JWTSecrets) > 0 {
		primarySecret = cfg.JWTSecrets[0]
	}
	authH := handlers.NewAuth(handlers.AuthDeps{
		Creds:  creds,
		Issuer: auth.NewIssuer(primarySecret, cfg.JWTIssuer, cfg.TokenTTL),
		Logger: logger,
	})
	if !authH.Enabled() {
		logger.Warn().Msg("auth/login disabled — set OPENSCRUB_USERS and OPENSCRUB_JWT_SECRET to enable")
	}

	router := api.NewRouter(api.Deps{
		Health:      healthH,
		Rules:       rulesH,
		Mitigations: mitigationsH,
		Snapshot:    snapshotH,
		Auth:        authH,
		Verifier:    verifier,
		DevMode:     devMode,
		Logger:      logger,
	})
	srv := api.NewServer(cfg.HTTPAddr, router, logger)

	// Background workers.
	var wg sync.WaitGroup

	// TTL sweeper.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runSweeper(ctx, ruleSvc, 30*time.Second, logger)
	}()

	// IOC puller.
	if cfg.ThreatFlowURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			puller := ioc.New(ioc.Config{
				BaseURL:  cfg.ThreatFlowURL,
				Token:    cfg.ThreatFlowToken,
				Interval: cfg.ThreatFlowInterval,
				RuleTTL:  24 * time.Hour,
			}, ruleSvc, logger, iocLogger)
			puller.Run(ctx)
		}()
	} else {
		logger.Info().Msg("OPENSCRUB_THREATFLOW_API_URL empty — IOC puller disabled")
	}

	// CITADEL mitigation watcher.
	if mitStoreAdapter != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := citadel.NewWatcher(citadelClient, mitStoreAdapter, citadel.WatcherConfig{
				MinDuration: cfg.MitigationMinDuration,
				TickEvery:   10 * time.Second,
				NodeName:    cfg.NodeName,
			}, logger)
			w.Run(ctx)
		}()
	}

	// Serve.
	if err := srv.ListenAndServe(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error().Err(err).Msg("http server stopped with error")
	}

	logger.Info().Msg("shutting down — waiting for workers")
	wg.Wait()
	logger.Info().Msg("openscrub stopped")
}

func buildDataplane(cfg config.Config, logger zerolog.Logger) dataplane.Client {
	switch cfg.DataplaneTransport {
	case "uds":
		logger.Info().Str("socket", cfg.DataplaneSocket).Msg("dataplane: UDS RPC client")
		return dataplane.NewUDSClient(cfg.DataplaneSocket, 2*time.Second)
	default:
		logger.Warn().Msg("dataplane: noop client (no kernel attach)")
		return dataplane.NewNoopClient()
	}
}

func runSweeper(ctx context.Context, svc *rules.Service, every time.Duration, log zerolog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := svc.SweepExpired(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("ttl sweep failed")
				continue
			}
			if n > 0 {
				log.Info().Int("expired", n).Msg("ttl sweep removed rules")
			}
		}
	}
}

// mitigationStoreAdapter bridges *db.MitigationStore (DB types) to
// citadel.MitigationStore (which uses citadel.MitigationRecord). It
// resolves rule metadata via the shared repo so each emitted event
// carries the cidr/type/source the auditor expects.
type mitigationStoreAdapter struct {
	repo  rules.Repo
	store *db.MitigationStore
}

func newMitigationStoreAdapter(repo rules.Repo, store *db.MitigationStore) citadel.MitigationStore {
	return &mitigationStoreAdapter{repo: repo, store: store}
}

func (a *mitigationStoreAdapter) PendingForEmit(ctx context.Context, minDuration time.Duration, limit int) ([]citadel.MitigationRecord, error) {
	rows, err := a.store.PendingForEmit(ctx, minDuration, limit)
	if err != nil {
		return nil, err
	}
	out := make([]citadel.MitigationRecord, 0, len(rows))
	for _, m := range rows {
		out = append(out, mitigationRecordFromRow(ctx, a.repo, m))
	}
	return out, nil
}

// mitigationRecordFromRow converts one persisted mitigation row into the
// wire shape CITADEL expects. Split out of PendingForEmit so the mapping
// (including the legacy rule-lookup fallback) can be unit tested against
// a rules.Repo without a live Postgres connection.
func mitigationRecordFromRow(ctx context.Context, repo rules.Repo, m db.Mitigation) citadel.MitigationRecord {
	rec := citadel.MitigationRecord{
		ID:             m.ID,
		StartedAt:      m.StartedAt,
		PacketsDropped: m.PacketsDropped,
		BytesDropped:   m.BytesDropped,
	}
	if m.RuleID.Valid {
		rec.RuleID = m.RuleID.UUID
	}
	if m.EndedAt != nil {
		rec.EndedAt = *m.EndedAt
	}
	if m.SrcIP != nil {
		rec.SrcIP = m.SrcIP.String()
	}
	// Prefer the snapshot captured on the mitigation row at insert
	// time (so a deleted parent rule still produces a complete
	// CITADEL payload). Fall back to a live rule lookup only if
	// the snapshot is empty (legacy rows from before 0002).
	if m.RuleCIDR != "" || m.RuleType != "" {
		ruleIDStr := ""
		if m.RuleID.Valid {
			ruleIDStr = m.RuleID.UUID.String()
		}
		rec.Rule = citadel.RuleSummary{
			ID:     ruleIDStr,
			CIDR:   m.RuleCIDR,
			Type:   m.RuleType,
			Source: m.RuleSource,
		}
	} else if m.RuleID.Valid {
		if r, err := repo.Get(ctx, m.RuleID.UUID); err == nil {
			rec.Rule = citadel.RuleSummary{
				ID:         r.ID.String(),
				CIDR:       r.CIDR,
				Type:       string(r.Type),
				PPS:        r.PPS,
				Port:       r.Port,
				TTLSeconds: r.TTLSeconds,
				Source:     r.Source,
			}
		} else {
			rec.Rule = citadel.RuleSummary{ID: m.RuleID.UUID.String(), Type: "unknown"}
		}
	} else {
		rec.Rule = citadel.RuleSummary{Type: "unknown"}
	}
	return rec
}

func (a *mitigationStoreAdapter) MarkEmitted(ctx context.Context, id uuid.UUID) error {
	return a.store.MarkEmitted(ctx, id)
}

func (a *mitigationStoreAdapter) MarkSending(ctx context.Context, id uuid.UUID, eventID string) error {
	return a.store.MarkSending(ctx, id, eventID)
}

func (a *mitigationStoreAdapter) MarkSent(ctx context.Context, id uuid.UUID) error {
	return a.store.MarkSent(ctx, id)
}

func (a *mitigationStoreAdapter) MarkFailed(ctx context.Context, id uuid.UUID, lastError string) error {
	return a.store.MarkFailed(ctx, id, lastError)
}

func (a *mitigationStoreAdapter) LookupByEventID(ctx context.Context, eventID string) (uuid.UUID, error) {
	return a.store.LookupByEventID(ctx, eventID)
}

// mitigationListAdapter bridges *db.MitigationStore (DB types) to
// handlers.MitigationLister (which exposes the wire view).
type mitigationListAdapter struct {
	store *db.MitigationStore
}

func newMitigationListAdapter(store *db.MitigationStore) handlers.MitigationLister {
	return &mitigationListAdapter{store: store}
}

func (a *mitigationListAdapter) List(ctx context.Context, since time.Time, ruleID uuid.UUID, limit int) ([]handlers.MitigationView, error) {
	rows, err := a.store.List(ctx, since, ruleID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]handlers.MitigationView, 0, len(rows))
	for _, m := range rows {
		out = append(out, mitigationViewFromRow(m))
	}
	return out, nil
}

// mitigationViewFromRow converts a persisted mitigation row into the
// handler's wire view. Split out of List so the conversion can be unit
// tested without a live Postgres connection.
func mitigationViewFromRow(m db.Mitigation) handlers.MitigationView {
	var ruleID uuid.UUID
	if m.RuleID.Valid {
		ruleID = m.RuleID.UUID
	}
	return handlers.MitigationViewFrom(
		m.ID, ruleID, m.StartedAt, m.EndedAt,
		m.PacketsDropped, m.BytesDropped, m.SrcIP, m.Emitted)
}

// lifecycleStoreAdapter bridges rules.MitigationStore (rules-package
// types) onto *db.MitigationStore (pgx-typed). Keeps the rules package
// free of pgx imports.
type lifecycleStoreAdapter struct {
	store *db.MitigationStore
}

func (a *lifecycleStoreAdapter) Insert(ctx context.Context, m rules.MitigationInsert) error {
	_, err := a.store.Insert(ctx, mitigationRowFromInsert(m))
	return err
}

// mitigationRowFromInsert converts a rules-package insert request into
// the DB row shape. Split out of Insert so the field mapping can be
// unit tested without a live Postgres connection.
func mitigationRowFromInsert(m rules.MitigationInsert) db.Mitigation {
	return db.Mitigation{
		ID:                  m.ID,
		RuleID:              uuid.NullUUID{UUID: m.RuleID, Valid: m.RuleID != uuid.Nil},
		RuleCIDR:            m.RuleCIDR,
		RuleType:            m.RuleType,
		RuleSource:          m.RuleSource,
		StartedAt:           m.StartedAt,
		SrcIP:               m.SrcIP,
		StartPacketsDropped: m.StartPacketsDropped,
		StartBytesDropped:   m.StartBytesDropped,
	}
}

func (a *lifecycleStoreAdapter) FinalizeForRule(ctx context.Context, ruleID uuid.UUID, endedAt time.Time, endPackets, endBytes int64) error {
	return a.store.FinalizeForRule(ctx, ruleID, endedAt, endPackets, endBytes)
}

func (a *lifecycleStoreAdapter) OpenRuleIDs(ctx context.Context) (map[uuid.UUID]struct{}, error) {
	return a.store.OpenRuleIDs(ctx)
}

// snapshotRulesAdapter implements handlers.SnapshotRulesSource. When
// the underlying repo is a *db.RuleStore the work is delegated to two
// SQL aggregates (one GROUP BY type, one GROUP BY family(cidr)) — the
// previous list-walk pulled up to 1k rows per /metrics/snapshot call
// every 5 s, which became the dominant query under load.
//
// MemoryRepo (dev mode) keeps the walking implementation since it has
// no SQL surface to delegate to.
type snapshotRulesAdapter struct {
	repo  rules.Repo
	store *db.RuleStore
}

func newSnapshotRulesAdapter(repo rules.Repo) handlers.SnapshotRulesSource {
	a := &snapshotRulesAdapter{repo: repo}
	if rs, ok := repo.(*db.RuleStore); ok {
		a.store = rs
	}
	return a
}

func (a *snapshotRulesAdapter) CountByType(ctx context.Context) (int, int, int, error) {
	if a.store != nil {
		return a.store.CountByType(ctx)
	}
	all, err := a.repo.List(ctx, "", 1000, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	var bl, rl, sc int
	for _, r := range all {
		switch r.Type {
		case rules.TypeBlocklist:
			bl++
		case rules.TypeRatelimit:
			rl++
		case rules.TypeSynCookie:
			sc++
		}
	}
	return bl, rl, sc, nil
}

func (a *snapshotRulesAdapter) V4V6Split(ctx context.Context) (int, int, error) {
	if a.store != nil {
		return a.store.CountBlocklistByFamily(ctx)
	}
	all, err := a.repo.List(ctx, rules.TypeBlocklist, 1000, 0)
	if err != nil {
		return 0, 0, err
	}
	var v4, v6 int
	for _, r := range all {
		p, err := rules.ParseCIDR(r.CIDR)
		if err != nil {
			continue
		}
		if p.Addr().Is4() {
			v4++
		} else {
			v6++
		}
	}
	return v4, v6, nil
}

// snapshotIOCAdapter implements handlers.SnapshotIOCSource by combining
// LastForSource(threatflow) with a count of rows in ioc_ingest_log.
type snapshotIOCAdapter struct{ store *db.IOCIngestLogStore }

func newSnapshotIOCAdapter(store *db.IOCIngestLogStore) handlers.SnapshotIOCSource {
	return &snapshotIOCAdapter{store: store}
}

func (a *snapshotIOCAdapter) LastIngest(ctx context.Context) (time.Time, int, error) {
	last, err := a.store.LastForSource(ctx, "threatflow")
	if err != nil {
		return time.Time{}, 0, err
	}
	return last.IngestedAt, last.Count, nil
}
