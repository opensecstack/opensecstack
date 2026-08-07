// Command cyberpath-server — CyberPath API server entrypoint.
//
// v1.0.0 wire-up: when a DB connection is available the server wires
// the live auth handlers (UserStore + Issuer + sessions), the IRFlow
// incoming webhook handler (HMAC-verified, cohort-creating), and the
// CITADEL outbox worker (drains the outbox table, signs deliveries,
// reports DLQ metrics). Without a DB the server still starts in
// degraded mode — the v0.0.1 stubs apply via api.Options nil-fallbacks.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/cyberpath/internal/api"
	"github.com/opensecstack/cyberpath/internal/api/handlers"
	"github.com/opensecstack/cyberpath/internal/auth"
	"github.com/opensecstack/cyberpath/internal/cert"
	"github.com/opensecstack/cyberpath/internal/citadel"
	"github.com/opensecstack/cyberpath/internal/config"
	"github.com/opensecstack/cyberpath/internal/content"
	"github.com/opensecstack/cyberpath/internal/db"
	"github.com/opensecstack/cyberpath/internal/docker"
	"github.com/opensecstack/cyberpath/internal/irflow"
	"github.com/opensecstack/cyberpath/internal/metrics"
	"github.com/opensecstack/cyberpath/internal/nis2"
	"github.com/opensecstack/cyberpath/internal/version"
	"github.com/opensecstack/cyberpath/internal/wireup"
	sdkcitadel "github.com/opensecstack/sdk/go/citadel"
)

type stubPinger struct{}

func (stubPinger) Ping(context.Context) error { return nil }

func main() {
	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "cyberpath").
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
	if err := cfg.Validate(); err != nil {
		logger.Fatal().Err(err).Msg("refusing to start: insecure config in production")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// DB (optional in dev — falls back to stub pinger).
	var (
		pinger        handlers.Pinger = stubPinger{}
		dbHandle      *db.DB
		contentSvc    *content.Service
		authHandlers  *handlers.AuthHandlers
		irflowWebhook *handlers.IRFlowWebhookHandler
		worker        *citadel.Worker
	)
	if cfg.DB.URL != "" || cfg.DB.Password != "" {
		d, err := db.New(ctx, cfg.DB.EffectiveURL(), int32(cfg.DB.MaxOpenConns))
		if err != nil {
			logger.Warn().Err(err).Msg("DB unavailable — continuing with stub pinger")
		} else {
			pinger = d
			dbHandle = d
			defer d.Close()
			logger.Info().Msg("DB connected")
		}
	}

	mreg := metrics.New()
	hs256Verifier := auth.NewHS256Verifier(cfg.Auth.ActiveSecrets(), cfg.Auth.Issuer)
	sinauthURL := cfg.Auth.SinauthURL
	if sinauthURL == "" {
		sinauthURL = "http://localhost:8100"
	}
	verifier := auth.NewDualVerifier(hs256Verifier, sinauthURL)

	// ── Outbound integration clients ─────────────────────────────────
	nis2Client := nis2.New(nis2.Options{
		BaseURL: cfg.NIS2.APIURL,
		Logger:  logger,
	})
	_ = irflow.New(irflow.Options{
		BaseURL:    cfg.IRFlow.APIURL,
		HMACSecret: cfg.IRFlow.WebhookSecret,
		Logger:     logger,
	})

	// ── Ed25519 cert signer ──────────────────────────────────────────────
	// Initialized before the DB block so it can be used inside it.
	// When no PEM key is configured, an ephemeral key is used (dev only —
	// warned by WarnIfInsecure above).
	certSigner, err := cert.NewSigner(cfg.Cert.SigningKeyPEM)
	if err != nil {
		logger.Fatal().Err(err).Msg("cert signer init failed")
	}
	logger.Info().Str("key_id", certSigner.KeyID()).Msg("cert signer ready")

	// ── DB-backed wire-up (auth + IRFlow + outbox worker) ────────────
	var (
		tracksHandler         *handlers.TracksHandler
		lessonsHandler        *handlers.LessonsHandler
		quizzesHandler        *handlers.QuizHandler
		labsHandler           *handlers.LabsHandler
		usersHandler          *handlers.UsersHandler
		enrollmentHandler     *handlers.EnrollmentHandler
		certificationsHandler *handlers.CertificationsHandler
		contentVersionsHandler *handlers.ContentVersionsHandler

		// Kept in outer scope so coverageHandler can call WithProgress after
		// the DB block without re-declaring inside it.
		outerProgressStore *db.ProgressStore
		outerTrackStore    *db.TrackStore
		outerLessonStore   *db.LessonStore

		// Kept in outer scope so the Docker terminal handler can reference it
		// after the DB block.
		outerLabStore *db.LabStore
	)
	if dbHandle != nil {
		userStore := db.NewUserStore(dbHandle.Pool)
		cohortStore := db.NewCohortStore(dbHandle.Pool)
		enrollmentStore := db.NewEnrollmentStore(dbHandle.Pool)
		auditStore := db.NewAuditEventStore(dbHandle.Pool)
		outboxStore := db.NewOutboxStore(dbHandle.Pool)
		webhookStore := db.NewWebhookStore(dbHandle.Pool)
		progressStore := db.NewProgressStore(dbHandle.Pool)
		certificationStore := db.NewCertificationStore(dbHandle.Pool)
		completionStore := db.NewCompletionStore(dbHandle.Pool)
		contentVersionStore := db.NewContentVersionStore(dbHandle.Pool)
		quizStore := db.NewQuizStore(dbHandle.Pool)
		labStore := db.NewLabStore(dbHandle.Pool)
		outerLabStore = labStore
		trackStore := db.NewTrackStore(dbHandle.Pool)
		moduleStore := db.NewModuleStore(dbHandle.Pool)
		lessonStore := db.NewLessonStore(dbHandle.Pool)
		outerProgressStore = progressStore
		outerTrackStore = trackStore
		outerLessonStore = lessonStore

		// Auth — only wire when a signing secret is configured.
		if cfg.Auth.Secret != "" {
			issuer, err := auth.NewIssuer(auth.IssuerConfig{
				SigningKey: []byte(cfg.Auth.Secret),
				Issuer:     cfg.Auth.Issuer,
				AccessTTL:  cfg.Auth.TokenTTL,
			})
			if err != nil {
				logger.Fatal().Err(err).Msg("issuer init failed")
			}
			sessions := db.NewDBSessionStore(dbHandle.Pool)
			ah, err := handlers.NewAuthHandlers(handlers.AuthDeps{
				Users:          wireup.AuthUsers(userStore),
				Sessions:       sessions,
				Issuer:         issuer,
				Logger:         &logger,
				Pepper:         []byte(cfg.Auth.Pepper),
				PepperPrevious: []byte(cfg.Auth.PepperPrevious),
			})
			if err != nil {
				logger.Fatal().Err(err).Msg("auth handlers init failed")
			}
			authHandlers = ah
			logger.Info().Msg("auth handlers wired")
		}

		// IRFlow incoming webhook handler.
		if cfg.IRFlow.WebhookSecret != "" {
			irflowWebhook = handlers.NewIRFlowWebhookHandler(handlers.IRFlowWebhookOptions{
				HMACSecret: cfg.IRFlow.WebhookSecret,
				Cohorts:    wireup.IRFlowCohorts(cohortStore, enrollmentStore, uuid.Nil),
				Audit:      wireup.IRFlowAudit(auditStore),
				Outbox:     wireup.IRFlowOutbox(outboxStore),
				Logger:     logger,
			})
			logger.Info().Msg("irflow webhook handler wired")
		}

		// CITADEL outbox worker.
		citadelClient := citadel.New(citadel.Config{
			BaseURL:    cfg.Citadel.APIURL,
			HMACSecret: cfg.Citadel.KeySecret,
			KeyID:      cfg.Citadel.KeyID,
			ProjectID:  cfg.Citadel.ProjectID,
			DryRun:     cfg.Citadel.DryRun,
		}, logger)
		worker = citadel.NewWorker(citadel.Options{
			Outbox:       wireup.WorkerOutbox(outboxStore),
			Webhooks:     wireup.WorkerWebhooks(webhookStore),
			Citadel:      citadelClient,
			Metrics:      wireup.WorkerMetrics(mreg),
			Logger:       logger,
			Workers:      2,
			BatchSize:    10,
			PollInterval: 2 * time.Second,
		})
		if err := worker.Start(ctx); err != nil {
			logger.Error().Err(err).Msg("outbox worker start failed")
			worker = nil
		} else {
			logger.Info().Msg("outbox worker started")
		}

		// MARSHAL governance client for certification revocation — a
		// discretionary admin action, distinct from the outbox worker's
		// citadelClient above (which only handles WORM audit-emit).
		// Left as a nil interface (skips the governance check) when
		// CITADEL is not configured — assigned only in the branch below
		// so handlers.CertHandlerDeps.Marshal stays a true nil interface
		// rather than a non-nil interface wrapping a nil *Client.
		var marshalClient handlers.MarshalEvaluator
		if cfg.Citadel.APIURL != "" {
			marshalClient = sdkcitadel.NewClient(cfg.Citadel.APIURL, nil)
		}

		// Certifications handler (cert signer initialized before DB block).
		certificationsHandler = handlers.NewCertificationsHandler(handlers.CertHandlerDeps{
			Certs:            certificationStore,
			Tracks:           trackStore,
			Completions:      completionStore,
			Signer:           certSigner,
			Outbox:           wireup.CertOutbox(outboxStore),
			Audit:            auditStore,
			Logger:           &logger,
			Marshal:          marshalClient,
			CitadelProjectID: cfg.Citadel.ProjectID,
		})
		contentVersionsHandler = handlers.NewContentVersionsHandler(contentVersionStore, &logger)
		logger.Info().Msg("certifications handler wired")

		// Content + learning handlers.
		tracksHandler = handlers.NewTracksHandler(trackStore, moduleStore, lessonStore, &logger)
		lessonsHandler = handlers.NewLessonsHandler(handlers.LessonsDeps{
			Lessons:         lessonStore,
			Progress:        progressStore,
			Audit:           auditStore,
			Logger:          &logger,
			Tracks:          trackStore,
			ContentVersions: contentVersionStore,
			Completions:     completionStore,
			Outbox:          outboxStore,
			CitadelProject:  cfg.Citadel.ProjectID,
			TrackCompletion: completionStore,
			CertIssuer:      certificationsHandler,
		})
		quizzesHandler = handlers.NewQuizHandler(quizStore, progressStore, auditStore, &logger)
		labsHandler = handlers.NewLabsHandler(labStore, auditStore, &logger)
		usersHandler = handlers.NewUsersHandler(progressStore, certificationStore, lessonStore, auditStore, &logger)
		enrollmentHandler = handlers.NewEnrollmentHandler(enrollmentStore, &logger)
		logger.Info().Msg("learning handlers wired")
	}


	// Docker provisioner — optional; disabled gracefully when Docker is
	// unavailable (e.g. CI environments without a daemon socket).
	var terminalHandler *handlers.TerminalHandler
	dockerProv, dockerErr := docker.New()
	if dockerErr != nil {
		logger.Warn().Err(dockerErr).Msg("Docker unavailable — lab containers disabled")
	} else {
		if labsHandler != nil {
			labsHandler.Docker = dockerProv
		}
		terminalHandler = &handlers.TerminalHandler{
			Labs:   outerLabStore,
			Docker: dockerProv,
			Logger: &logger,
		}
		logger.Info().Msg("Docker provisioner wired")
	}

	// ── Content service ──────────────────────────────────────────────
	if cfg.Content.Path != "" {
		var publisher *content.Publisher
		if dbHandle != nil {
			publisher = content.NewPublisher(dbHandle.Pool, nil, nil)
		}
		contentSvc = content.NewService(cfg.Content.Path, publisher)
	}

	// ── HTTP handlers ────────────────────────────────────────────────
	coverageHandler := handlers.NewCoverageHandler(&logger)
	if outerProgressStore != nil && outerTrackStore != nil && outerLessonStore != nil {
		coverageHandler.WithProgress(outerProgressStore, outerTrackStore, outerLessonStore)
	}
	var contentAdmin *handlers.ContentAdminHandler
	if contentSvc != nil {
		contentAdmin = handlers.NewContentAdminHandler(contentSvc, &logger)
	}

	// /readyz only reports nis2compass connectivity when NIS2_BASE_URL
	// (cfg.NIS2.APIURL) is actually configured — an unconfigured client
	// would report "unreachable" forever in dev, which is noise, not
	// signal. Passed as a nil handlers.NIS2HealthChecker (not a
	// typed-nil *nis2.Client) so Readyz's nil check works correctly.
	var nis2Checker handlers.NIS2HealthChecker
	if cfg.NIS2.APIURL != "" {
		nis2Checker = nis2Client
	}

	router := api.NewRouter(api.Options{
		Config:        cfg,
		Logger:        &logger,
		Pinger:        pinger,
		Metrics:       mreg,
		Verifier:      verifier,
		NIS2:          nis2Checker,
		Auth:          authHandlers,
		IRFlowWebhook: irflowWebhook,
		Coverage:      coverageHandler,
		ContentAdmin:  contentAdmin,
		Tracks:          tracksHandler,
		Lessons:         lessonsHandler,
		Quizzes:         quizzesHandler,
		Labs:            labsHandler,
		Users:           usersHandler,
		Terminal:        terminalHandler,
		Enrollments:     enrollmentHandler,
		Certifications:  certificationsHandler,
		ContentVersions: contentVersionsHandler,
	})

	srv := &http.Server{
		Addr:         cfg.Server.HTTPAddr,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	logger.Info().Str("addr", cfg.Server.HTTPAddr).Msg("cyberpath started")

	select {
	case sig := <-sigCh:
		logger.Info().Str("signal", sig.String()).Msg("shutdown signal received")
	case err := <-errCh:
		logger.Error().Err(err).Msg("server error")
	}

	handlers.Ready.Store(false)
	drain := cfg.Server.DrainGrace
	if drain <= 0 {
		drain = 5 * time.Second
	}
	time.Sleep(drain)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("shutdown error")
		os.Exit(1)
	}

	// Stop the outbox worker — cancel ctx then wait for goroutines to drain.
	cancel()
	if worker != nil {
		worker.Wait()
		logger.Info().Msg("outbox worker stopped")
	}
	logger.Info().Msg("cyberpath stopped cleanly")
}
