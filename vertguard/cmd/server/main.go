// Command vertguard-server — VertGuard API server.
//
// STATUS: Phase 4.1 v0.1.0-alpha.0 — Module 3 (Prompt Injection) +
// Module 4 (AI Threat Feed embedded ATLAS) functional. DB + auth +
// metrics wired. CITADEL integration (VG-015), ThreatFlow push
// (VG-015), C2PA (VG-011) pending.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/api"
	"github.com/opensecstack/vertguard/internal/api/handlers"
	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/auth/denylist"
	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/db"
	"github.com/opensecstack/vertguard/internal/media"
	"github.com/opensecstack/vertguard/internal/metrics"
	"github.com/opensecstack/vertguard/internal/ml"
	"github.com/opensecstack/vertguard/internal/identity"
	iocpkg "github.com/opensecstack/vertguard/internal/ioc"
	"github.com/opensecstack/vertguard/internal/phishing"
	"github.com/opensecstack/vertguard/internal/prompt"
	"github.com/opensecstack/vertguard/internal/ratelimit"
	"github.com/opensecstack/vertguard/internal/threatfeed/atlas"
	"github.com/opensecstack/vertguard/internal/threatfeed/webhook"
	"github.com/opensecstack/vertguard/internal/version"
	webhookv2 "github.com/opensecstack/vertguard/internal/webhook"
)

// stubPinger is used when the DB can't start (e.g. dev mode without Postgres).
type stubPinger struct{}

func (stubPinger) Ping(context.Context) error { return nil }

func main() {
	logger := zerolog.New(os.Stdout).
		With().
		Timestamp().
		Str("service", "vertguard").
		Str("version", version.Version).
		Str("commit", version.GitCommit).
		Logger()

	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("config load failed")
	}

	for _, w := range cfg.WarnIfInsecure() {
		logger.Warn().Msg("WARNING: " + w)
	}

	// Production gate: refuse to start when VG_ENV=production (or GO_ENV)
	// and the config carries dev-only / insecure defaults. See
	// internal/config.EnforceProductionGate. Closes security-checklist
	// row 2.10.
	if err := cfg.EnforceProductionGate(); err != nil {
		logger.Fatal().Err(err).Msg("refusing to start: insecure config detected in production environment")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── DB ────────────────────────────────────────────────────────
	var pinger handlers.Pinger = stubPinger{}
	var store *db.DB
	if cfg.DB.Password != "" || cfg.DB.Host != "" {
		d, err := db.New(ctx, cfg.DB.URL(), int32(cfg.DB.MaxOpenConns), int32(cfg.DB.MinConns))
		if err != nil {
			logger.Warn().Err(err).Msg("DB unavailable — continuing with stub pinger (scans will not persist)")
		} else {
			store = d
			pinger = d
			defer d.Close()
			logger.Info().Msg("DB connected")
		}
	}

	// ── Metrics ───────────────────────────────────────────────────
	mreg := metrics.New()

	// ── Auth ──────────────────────────────────────────────────────
	// Dual-secret rotation: ActiveSecrets returns up to three secrets
	// in priority order (primary, next, previous). The verifier accepts
	// any of them; first match wins. See docs/secrets-management.md.
	activeSecrets := cfg.Auth.ActiveSecrets()
	activeSlots := cfg.Auth.ActiveSecretSlots()
	var verifier *auth.Verifier
	if len(activeSecrets) == 0 {
		// Preserve legacy "empty secret => dev posture" behaviour: the
		// WarnIfInsecure() call above already screamed about it. Fall
		// back to the single-secret constructor which tolerates "".
		verifier = auth.NewVerifier(cfg.Auth.Secret, cfg.Auth.Issuer)
	} else {
		verifier = auth.NewVerifierMulti(activeSecrets, cfg.Auth.Issuer)
	}
	verifier.SetMetrics(metrics.NewAuthMetricsAdapter(mreg))
	if len(activeSecrets) > 1 {
		logger.Warn().
			Int("count", len(activeSecrets)).
			Strs("slots", activeSlots).
			Msgf("JWT verifier accepting %d secrets (rotation in progress)", len(activeSecrets))
	}

	// ── ML enricher (Phase 4.2) ──────────────────────────────────
	// Soft-fail by design: a failed dial here logs a warning and the
	// scanners fall back to regex-only. NEVER abort startup.
	var promptMLEnricher prompt.MLEnricher
	var phishingMLEnricher phishing.MLEnricher
	var mediaMLEnricher handlers.MediaMLEnricher
	var mlClient *ml.Client
	var adminMLH *handlers.AdminMLHandler
	if cfg.ML.Enabled && cfg.ML.GRPCURL != "" {
		c, err := ml.New(ml.Config{
			GRPCURL:     cfg.ML.GRPCURL,
			Timeout:     cfg.ML.Timeout,
			Enabled:     cfg.ML.Enabled,
			AlwaysScore: cfg.ML.AlwaysScore,
		}, logger, metrics.NewMLMetricsAdapter(mreg))
		if err != nil {
			logger.Warn().Err(err).Msg("ML enricher dial failed — scanners will fall back to regex-only")
		} else {
			mlClient = c
			promptMLEnricher = ml.PromptEnricher{C: c}
			phishingMLEnricher = ml.PhishingEnricher{C: c}
			mediaMLEnricher = ml.MediaEnricher{C: c}
			adminMLH = handlers.NewAdminMLHandler(c)
			defer func() {
				if err := c.Close(); err != nil {
					logger.Warn().Err(err).Msg("ml client close")
				}
			}()
			logger.Info().
				Str("grpc", cfg.ML.GRPCURL).
				Bool("always_score", cfg.ML.AlwaysScore).
				Msg("ML enricher enabled")
		}
	}

	// ── Module 3 — Prompt Injection ───────────────────────────────
	// VG-003: load curated rule pack + token-level heuristics; fall
	// back to DefaultLibrary if the pack is missing or invalid so a
	// bad path on disk never aborts startup.
	scanner, ruleErr := prompt.NewEngine(prompt.EngineConfig{
		RulePackPath:   cfg.Prompt.RulePackPath,
		CleanThreshold: cfg.Prompt.CleanThreshold,
		BlockThreshold: cfg.Prompt.BlockThreshold,
		MaxInputBytes:  int(cfg.Prompt.MaxInputSize),
	})
	if ruleErr != nil {
		logger.Warn().Err(ruleErr).Str("path", cfg.Prompt.RulePackPath).
			Msg("prompt rule pack load failed; falling back to DefaultLibrary")
	}
	// VG-003: subprocess ML backend kicks in only when the gRPC ML
	// path above is not active and a binary path is configured.
	if promptMLEnricher == nil && cfg.Prompt.MLBinaryPath != "" {
		promptMLEnricher = prompt.MLBackendAdapter{B: prompt.NewMLExec(prompt.MLExecConfig{
			BinaryPath:  cfg.Prompt.MLBinaryPath,
			Timeout:     cfg.Prompt.MLTimeout,
			AlwaysScore: cfg.ML.AlwaysScore,
		})}
		logger.Info().Str("binary", cfg.Prompt.MLBinaryPath).Msg("prompt ML subprocess backend enabled")
	}
	promptH := handlers.NewPromptHandler(
		scanner, store,
		metrics.NewPromptMetricsAdapter(mreg),
	)
	promptH.ML = promptMLEnricher
	// Tenant lets CITADEL evidence rows carry the owning project/tenant
	// for cross-cutting RBAC. ProjectID is the canonical source today;
	// warn if empty so operators notice the gap when CITADEL is wired
	// but evidence still lacks tenant attribution.
	promptH.Tenant = cfg.Citadel.ProjectID
	if promptH.Tenant == "" && cfg.Citadel.Enabled {
		logger.Warn().Msg("CITADEL enabled but cfg.Citadel.ProjectID is empty — evidence rows will be untagged")
	}
	logger.Info().
		Int("patterns_loaded", len(prompt.DefaultLibrary)).
		Msg("Module 3 (Prompt Injection) initialised")

	// ── VG-015 — outbound webhook subscribers ────────────────────
	// Built before CITADEL so the dispatcher can be wrapped around
	// the citadel client below — a FanoutEmitter pushes every
	// EmitAsync onto the outbox in addition to the WORM ledger.
	var (
		webhookStore      *webhookv2.Store
		webhookDispatcher *webhookv2.Dispatcher
		webhookSubH       *handlers.WebhookSubscribersHandler
	)
	if cfg.Webhook.Enabled && store != nil {
		webhookStore = webhookv2.NewStore(store.Pool)
		webhookDispatcher = webhookv2.NewDispatcher(webhookv2.Config{
			Enabled:             cfg.Webhook.Enabled,
			MaxRetries:          cfg.Webhook.MaxRetries,
			BackoffBase:         cfg.Webhook.BackoffBase,
			OutboxFlushInterval: cfg.Webhook.OutboxFlushInterval,
			RequestTimeout:      cfg.Webhook.RequestTimeout,
		}, webhookStore, webhookStore, logger, mreg)
		webhookDispatcher.Start()
		defer webhookDispatcher.Stop()
		webhookSubH = handlers.NewWebhookSubscribersHandler(webhookStore, webhookDispatcher)
		logger.Info().Msg("VG-015 outbound webhook subscribers enabled")
	} else if cfg.Webhook.Enabled {
		logger.Warn().Msg("VG-015 webhook subscribers enabled but DB not connected — feature disabled")
	}

	// ── CITADEL WORM emit ────────────────────────────────────────
	if cfg.Citadel.Enabled && cfg.Citadel.EffectiveBaseURL() != "" {
		// Loud warn when both legacy scalar + multi-slot are set so the
		// operator notices the ambiguity (multi-slot wins; the scalar is
		// only consulted when HMACSecrets is empty).
		if cfg.Citadel.CitadelHMACRotationCollision() {
			logger.Warn().Msg(
				"CITADEL HMAC: both scalar (VERTGUARD_CITADEL_HMAC_SECRET / KEY_SECRET) " +
					"and multi-slot (VERTGUARD_CITADEL_HMAC_SECRETS) are set — multi-slot wins; " +
					"clear the scalar to silence this warning")
		}
		cclient := citadel.New(citadel.Config{
			BaseURL:     cfg.Citadel.EffectiveBaseURL(),
			HMACSecret:  cfg.Citadel.EffectiveHMACSecret(),
			HMACSecrets: cfg.Citadel.EffectiveHMACSecrets(),
			KeyID:       cfg.Citadel.KeyID,
			KeyIDs:      cfg.Citadel.EffectiveKeyIDs(),
			ProjectID:   cfg.Citadel.ProjectID,
			DryRun:      cfg.Citadel.DryRun,
			AsyncBuffer: cfg.Citadel.AsyncBuffer,
		}, logger, metrics.NewCitadelMetricsAdapter(mreg))
		// VG-015: when subscribers are configured, wrap the citadel
		// client so every emitted event also fans out to the outbox.
		// Handlers see one WORMEmitter regardless.
		if webhookDispatcher != nil {
			promptH.Citadel = webhookv2.NewFanoutEmitter(cclient, webhookDispatcher)
		} else {
			promptH.Citadel = cclient
		}
		defer func() {
			if err := cclient.Close(); err != nil {
				logger.Warn().Err(err).Msg("citadel close")
			}
		}()
		logger.Info().Str("base_url", cfg.Citadel.EffectiveBaseURL()).Msg("CITADEL WORM emitter enabled")
	}

	// ── Module 5 — Phishing (rule-based v1) ─────────────────────
	var phishingH *handlers.PhishingHandler
	if cfg.Phishing.Enabled {
		phScanner := phishing.NewScanner(
			phishing.DefaultLibrary,
			cfg.Phishing.CleanThreshold,
			cfg.Phishing.BlockThreshold,
			int(cfg.Phishing.MaxInputSize),
		)
		phishingH = handlers.NewPhishingHandler(
			phScanner, store,
			metrics.NewPhishingMetricsAdapter(mreg),
		)
		phishingH.ML = phishingMLEnricher
		// Reuse the prompt module's CITADEL emitter when present —
		// same client, different event_type at emit time.
		if promptH.Citadel != nil {
			phishingH.Citadel = promptH.Citadel
		}
		logger.Info().
			Int("indicators_loaded", len(phishing.DefaultLibrary)).
			Msg("Module 5 (Phishing — rule-based v1) initialised")
	}

	// ── Module 6 — Identity Verification (rule-based v1) ────────
	var identityH *handlers.IdentityHandler
	if cfg.Identity.Enabled {
		idScanner := identity.NewScanner(
			identity.DefaultLibrary,
			cfg.Identity.CleanThreshold,
			cfg.Identity.BlockThreshold,
			int(cfg.Identity.MaxInputSize),
			cfg.Identity.ReplayWindow,
			cfg.Identity.ReplayThreshold,
		)
		idScanner.StartJanitor()
		defer idScanner.Stop()
		identityH = handlers.NewIdentityHandler(
			idScanner, store,
			metrics.NewIdentityMetricsAdapter(mreg),
		)
		if mlClient != nil {
			identityH.ML = ml.NewIdentityAdapter(mlClient)
		}
		// Reuse the prompt module's CITADEL emitter when present —
		// same client, different event_type at emit time.
		if promptH.Citadel != nil {
			identityH.Citadel = promptH.Citadel
		}
		logger.Info().
			Int("indicators_loaded", len(identity.DefaultLibrary)).
			Msg("Module 6 (Identity Verification — rule-based v1) initialised")
	}

	// ── Module 4 — AI Threat Feed ─────────────────────────────────
	threatFeedH := handlers.NewThreatFeedHandler()
	threatFeedH.Tenant = cfg.Citadel.ProjectID
	if promptH.Citadel != nil {
		threatFeedH.Citadel = promptH.Citadel
	}
	logger.Info().Msg("Module 4 (AI Threat Feed) initialised with embedded ATLAS")

	// ── VG-006 — Persistent IOC store + community-feed puller ────
	// Store binds to the existing pgxpool when available; the puller is
	// only started when ioc.enabled and at least one source is wired.
	var iocPullerCancel context.CancelFunc
	if cfg.IOC.Enabled && store != nil {
		iocStore := iocpkg.NewStore(store.Pool)
		threatFeedH.Store = iocStore

		var sources []iocpkg.SourceSpec
		if cfg.IOC.MISPURL != "" {
			auth := cfg.IOC.MISPToken
			if auth != "" && !strings.HasPrefix(auth, "Bearer ") {
				auth = "Bearer " + auth
			}
			sources = append(sources, iocpkg.SourceSpec{
				Source:   iocpkg.MISPSource{URL: cfg.IOC.MISPURL, AuthHeader: auth},
				Interval: cfg.IOC.Interval,
			})
		}
		if cfg.IOC.AbuseChEnabled {
			sources = append(sources, iocpkg.SourceSpec{
				Source: iocpkg.AbuseChSource{
					URL:     cfg.IOC.AbuseChURLs,
					HashURL: cfg.IOC.AbuseChHashes,
				},
				Interval: cfg.IOC.Interval,
			})
		}
		for _, sc := range cfg.IOC.Sources {
			if !sc.Enabled {
				continue
			}
			interval := sc.Interval
			if interval <= 0 {
				interval = cfg.IOC.Interval
			}
			switch sc.Type {
			case "misp":
				sources = append(sources, iocpkg.SourceSpec{
					Source:   iocpkg.MISPSource{NameTag: sc.Name, URL: sc.URL, AuthHeader: sc.AuthHeader},
					Interval: interval,
				})
			case "abusech":
				sources = append(sources, iocpkg.SourceSpec{
					Source:   iocpkg.AbuseChSource{NameTag: sc.Name, URL: sc.URL, HashURL: sc.HashURL},
					Interval: interval,
				})
			case "file":
				sources = append(sources, iocpkg.SourceSpec{
					Source:   iocpkg.FileSource{NameTag: sc.Name, Path: sc.Path},
					Interval: interval,
				})
			}
		}

		puller := iocpkg.New(iocpkg.PullerConfig{
			Store:         iocStore,
			Sources:       sources,
			Allow:         iocpkg.NewAllowlist(cfg.IOC.Allowlist),
			Metrics:       metrics.NewIOCMetricsAdapter(mreg),
			Logger:        logger,
			Citadel:       promptH.Citadel,
			Tenant:        cfg.Citadel.ProjectID,
			SweepInterval: cfg.IOC.SweepInterval,
		})
		var pullerCtx context.Context
		pullerCtx, iocPullerCancel = context.WithCancel(ctx)
		go puller.Run(pullerCtx)
		logger.Info().
			Int("sources", len(sources)).
			Dur("sweep", cfg.IOC.SweepInterval).
			Msg("VG-006 IOC store + puller started")
	} else if cfg.IOC.Enabled {
		logger.Warn().Msg("VG-006 IOC store enabled but DB not connected — puller disabled")
	}
	if iocPullerCancel != nil {
		defer iocPullerCancel()
	}

	// ATLAS syncer powers periodic + on-demand sync. We construct it
	// even when no remote URL is configured — the embedded Initial()
	// set seeds the cache so admin sync can still be invoked (will
	// attempt the default upstream URL).
	atlasSyncer := atlas.NewSyncer(atlas.SyncerConfig{}, logger,
		nil, // metrics adapter wiring lives in VG-006; nil-safe today
	)
	go atlasSyncer.RunPeriodic(ctx)

	// ── ThreatFlow webhook publisher (VG-006) ────────────────────
	var webhookAdmin *handlers.WebhookAdminHandler
	if cfg.ThreatFlow.APIURL != "" {
		var seed []webhook.Subscriber
		if cfg.ThreatFlow.WebhookSecret != "" {
			seed = append(seed, webhook.Subscriber{
				ID:         "default",
				URL:        cfg.ThreatFlow.APIURL,
				HMACSecret: cfg.ThreatFlow.WebhookSecret,
				Active:     true,
			})
		}
		pub := webhook.New(logger, metrics.NewThreatFlowMetricsAdapter(mreg), seed)
		webhookAdmin = handlers.NewWebhookAdminHandler(pub)
		logger.Info().Int("seed_subscribers", len(seed)).Msg("ThreatFlow webhook publisher enabled")
	}

	// ── Audit subsystem ──────────────────────────────────────────
	// Logger sink is always on; DB sink + admin query handler attach
	// only when a real store is connected.
	auditSinks := []audit.Sink{audit.NewLoggerSink(&logger)}
	var auditH *handlers.AuditHandler
	if store != nil {
		auditSinks = append(auditSinks, audit.NewDBSink(store))
		auditH = handlers.NewAuditHandler(store)
	}
	auditSink := audit.NewMultiSink(&logger, auditSinks...)
	logger.Info().Int("sinks", len(auditSinks)).Msg("audit subsystem initialised")

	// ── JWT denylist (revocation) ────────────────────────────────
	// DB-backed when available; in-memory fallback keeps dev mode usable.
	var denylistStore denylist.Store
	denylistKind := "memory"
	if store != nil {
		denylistStore = db.NewDenylistStore(store)
		denylistKind = "db"
	} else {
		denylistStore = denylist.NewMemoryStore()
	}
	denylistCache := denylist.NewCache(
		denylistStore,
		denylist.WithRefreshInterval(denylist.DefaultRefreshInterval),
		denylist.WithLogger(&logger),
		denylist.WithMetrics(metrics.NewDenylistMetricsAdapter(mreg)),
	)
	if err := denylistCache.Refresh(ctx); err != nil {
		// Fail open: empty snapshot is safer than aborting the server.
		logger.Warn().Err(err).Msg("initial denylist refresh failed; starting with empty snapshot")
	}
	go denylistCache.Run(ctx)
	defer denylistCache.Close()
	denylistAdminH := handlers.NewDenylistAdminHandler(denylistStore, denylistCache, auditSink, &logger)
	logger.Info().
		Str("store", denylistKind).
		Dur("refresh", denylist.DefaultRefreshInterval).
		Msg("denylist subsystem initialised")

	// ── Admin: ATLAS sync + pattern reload ───────────────────────
	adminMetrics := metrics.NewAdminMetricsAdapter(mreg)
	adminAtlasH := handlers.NewAdminAtlasHandler(atlasSyncer, auditSink, &logger, adminMetrics)
	var phScannerForReload *phishing.Scanner
	if phishingH != nil {
		phScannerForReload = phishingH.Scanner
	}
	adminPatternsH := handlers.NewAdminPatternsHandler(
		scanner, phScannerForReload,
		cfg.Prompt.CustomPatternsPath, cfg.Phishing.ModelsPath,
		auditSink, &logger, adminMetrics,
	)

	// ── Module 1 — Media Authenticity (C2PA) ─────────────────────
	// Wired when VERTGUARD_MEDIA_BINARY_PATH points to the compiled
	// c2pa-verify CLI. Gracefully absent when the binary is not
	// available (handler returns 503 rather than panicking at startup).
	var mediaH *handlers.MediaHandler
	if cfg.Media.BinaryPath != "" {
		// VG-011-c: load trust anchors + CRL. Failures here downgrade
		// to "no anchors loaded" rather than aborting startup —
		// every chain then resolves to "untrusted", which is a
		// signalling status, not a fatal error. Operators flip
		// RequireTrust=true to make untrusted return 422.
		ts, tsErr := media.NewTrustStore(cfg.Media.TrustAnchorsDir)
		if tsErr != nil {
			logger.Warn().Err(tsErr).Str("dir", cfg.Media.TrustAnchorsDir).
				Msg("media trust store load failed; chains will resolve as untrusted")
		}
		crl, crlErr := media.NewRevocationList(cfg.Media.RevocationListPath)
		if crlErr != nil {
			logger.Warn().Err(crlErr).Str("path", cfg.Media.RevocationListPath).
				Msg("media revocation list load failed; revocation checks disabled")
		}
		mediaVerifier := media.New(media.Config{
			BinaryPath:  cfg.Media.BinaryPath,
			Timeout:     cfg.Media.Timeout,
			MaxFileSize: cfg.Media.MaxSize,
			TrustStore:  ts,
			Revocation:  crl,
		})
		// Background reload: mtime-poll on the configured interval +
		// SIGHUP for explicit reloads. Both watchers stop when the
		// process context cancels.
		mediaStop := make(chan struct{})
		go func() { <-ctx.Done(); close(mediaStop) }()
		if ts != nil {
			go ts.WatchChanges(mediaStop, cfg.Media.ReloadInterval)
		}
		if crl != nil {
			go crl.WatchChanges(mediaStop, cfg.Media.ReloadInterval)
		}
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for range sighup {
				if ts != nil {
					_ = ts.Reload()
				}
				if crl != nil {
					_ = crl.Reload()
				}
				logger.Info().Msg("media trust store + CRL reloaded on SIGHUP")
			}
		}()
		var mediaStore handlers.MediaStore
		if store != nil {
			mediaStore = store
		}
		mediaH = handlers.NewMediaHandler(mediaVerifier, mediaStore, logger)
		mediaH.RequireTrust = cfg.Media.RequireTrust
		mediaH.ML = mediaMLEnricher
		logger.Info().
			Str("binary", cfg.Media.BinaryPath).
			Bool("require_trust", cfg.Media.RequireTrust).
			Msg("Module 1 (Media Authenticity — C2PA) initialised")
	} else {
		logger.Info().Msg("Module 1 (Media Authenticity) disabled — VERTGUARD_MEDIA_BINARY_PATH not set")
	}

	// ── ThreatFlow webhook receiver ───────────────────────────────
	// Accepts inbound IOC push events from ThreatFlow, verifies the
	// HMAC signature, and re-publishes to VertGuard's own subscribers.
	var threatflowRecv *handlers.ThreatflowReceiver
	if cfg.ThreatFlow.WebhookSecret != "" {
		var pub *webhook.Publisher
		if webhookAdmin != nil {
			pub = webhookAdmin.Pub
		}
		threatflowRecv = handlers.NewThreatflowReceiver(cfg.ThreatFlow.WebhookSecret, pub, logger)
		logger.Info().Msg("ThreatFlow webhook receiver enabled")
	}

	// ── Rate limiter ─────────────────────────────────────────────
	var rl *ratelimit.Limiter
	var rlAdminH *handlers.RateLimitAdminHandler
	rlMetrics := metrics.NewRateLimitMetricsAdapter(mreg)
	if cfg.Server.RateLimitEnabled && cfg.Server.RateLimitRPS > 0 {
		rl = ratelimit.New(ratelimit.Config{
			RPS:   cfg.Server.RateLimitRPS,
			Burst: cfg.Server.RateLimitBurst,
		})
		// Same metrics adapter satisfies both rate-limit Metrics and
		// override OverrideHook surfaces.
		rl.SetOverrideHook(rlMetrics)
		defer rl.Stop()

		// DB-backed when available; in-memory fallback keeps dev mode usable.
		var rlOverrideStore ratelimit.OverrideStore
		rlOverrideKind := "memory"
		if store != nil {
			rlOverrideStore = db.NewRateLimitOverrideStore(store)
			rlOverrideKind = "db"
		} else {
			rlOverrideStore = ratelimit.NewMemoryOverrideStore()
		}
		go rl.RunRefresh(ctx, rlOverrideStore, 30*time.Second, &logger)
		rlAdminH = handlers.NewRateLimitAdminHandler(rlOverrideStore, rl, auditSink, &logger)

		logger.Info().
			Float64("rps", cfg.Server.RateLimitRPS).
			Int("burst", cfg.Server.RateLimitBurst).
			Str("override_store", rlOverrideKind).
			Msg("rate limiter enabled")
	}

	// ── HTTP server ───────────────────────────────────────────────
	srv := api.New(api.Options{
		Config:             cfg,
		Logger:             &logger,
		Pinger:             pinger,
		Prompt:             promptH,
		Phishing:           phishingH,
		Identity:           identityH,
		ThreatFeed:         threatFeedH,
		Media:              mediaH,
		ThreatflowReceiver: threatflowRecv,
		WebhookAdmin:       webhookAdmin,
		AdminAtlas:         adminAtlasH,
		AdminPatterns:      adminPatternsH,
		AdminML:          adminMLH,
		Audit:            auditH,
		AuditSink:        auditSink,
		AuditMetrics:     metrics.NewAuditMetricsAdapter(mreg),
		Metrics:          mreg,
		Authenticator:    verifier,
		TokenRevoker:     denylistCache,
		Denylist:         denylistAdminH,
		RateLimitAdmin:   rlAdminH,
		RateLimiter:      rl,
		RateLimitMetrics: rlMetrics,
		Auth:             handlers.NewAuthHandler(),
		WebhookSubscribers: webhookSubH,
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	logger.Info().
		Int("port", cfg.Server.Port).
		Str("log_level", cfg.Server.LogLevel).
		Msg("vertguard started")

	select {
	case sig := <-sigCh:
		logger.Info().Str("signal", sig.String()).Msg("shutdown signal received")
	case err := <-errCh:
		logger.Error().Err(err).Msg("server error")
	}

	// Flip readiness off FIRST so the load balancer drains us before we
	// stop accepting connections. Existing in-flight requests still
	// complete during srv.Shutdown's grace window.
	handlers.Ready.Store(false)
	drainGrace := cfg.Server.DrainGrace
	if drainGrace <= 0 {
		drainGrace = 5 * time.Second
	}
	logger.Info().Dur("drain_grace", drainGrace).Msg("readiness flipped off; awaiting LB drain")
	time.Sleep(drainGrace)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("shutdown error")
		os.Exit(1)
	}

	// CITADEL queue + ATLAS goroutines drain via the deferred Close
	// hooks above; log the boundary so operators can correlate the
	// drain window in dashboards.
	logger.Info().Msg("draining CITADEL queue")
	// drain logging — defers run after this returns; explicit message
	// so the timeline in logs is unambiguous.
	defer logger.Info().Msg("drain complete")

	logger.Info().Msg("vertguard stopped cleanly")
}
