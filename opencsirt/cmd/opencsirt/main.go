// Command opencsirt is the OpenCSIRT API server.
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
	"github.com/rs/zerolog/log"

	"github.com/opensecstack/opencsirt/internal/advisory"
	"github.com/opensecstack/opencsirt/internal/api"
	"github.com/opensecstack/opencsirt/internal/api/handlers"
	"github.com/opensecstack/opencsirt/internal/auth"
	"github.com/opensecstack/opencsirt/internal/citadel"
	"github.com/opensecstack/opencsirt/internal/config"
	"github.com/opensecstack/opencsirt/internal/constituency"
	"github.com/opensecstack/opencsirt/internal/db"
	"github.com/opensecstack/opencsirt/internal/incident"
	"github.com/opensecstack/opencsirt/internal/integrations"
	"github.com/opensecstack/opencsirt/internal/version"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger := log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	cfg, err := config.FromEnv()
	if err != nil {
		logger.Fatal().Err(err).Msg("config load")
	}
	logger.Info().Str("version", version.Version).Str("config", cfg.String()).Msg("opencsirt: starting")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── DB pool ──
	var pool *db.Pool
	if cfg.DBURL != "" {
		pool, err = db.Open(ctx, cfg.DBURL, cfg.DBMaxConns)
		if err != nil {
			logger.Fatal().Err(err).Msg("db open")
		}
		defer pool.Close()
	} else if !cfg.DevMode {
		logger.Fatal().Msg("OPENCSIRT_DB_URL required outside dev mode")
	}

	if pool == nil {
		logger.Warn().Msg("running in dev mode without DB — most endpoints will fail")
	}

	// ── Stores ──
	var (
		constituencyStore *db.ConstituencyStore
		incidentStore     *db.IncidentStore
		advisoryStore     *db.AdvisoryStore
		outboxStore       *db.OutboxStore
		auditStore        *db.AuditStore
		iocIngestStore    *db.IOCIngestStore
		peerStore         *db.PeerStore
	)
	if pool != nil {
		constituencyStore = db.NewConstituencyStore(pool)
		incidentStore = db.NewIncidentStore(pool)
		advisoryStore = db.NewAdvisoryStore(pool)
		outboxStore = db.NewOutboxStore(pool)
		auditStore = db.NewAuditStore(pool)
		iocIngestStore = db.NewIOCIngestStore(pool)
		peerStore = db.NewPeerStore(pool)
	}

	// ── Auth ──
	secrets := [][]byte{cfg.JWTSecret}
	if len(cfg.JWTSecret) == 0 && cfg.DevMode {
		secrets = [][]byte{[]byte("dev-secret-do-not-use-in-prod-aaaaaaaaaaaa")}
	}
	authn, err := auth.NewWithSinauth(secrets, cfg.JWTIssuer, cfg.TokenTTL, cfg.PasswordPepper, cfg.Users, cfg.SinauthURL)
	if err != nil {
		logger.Fatal().Err(err).Msg("auth init")
	}
	if cfg.DevMode && len(cfg.JWTSecret) == 0 {
		logger.Warn().Msg("OPENCSIRT_JWT_SECRET not set — using insecure dev secret; NEVER use in production")
	}

	// ── CITADEL ──
	citadelClient := citadel.New(cfg.CitadelAPIURL, cfg.CitadelHMACSecrets, cfg.CitadelKeyID, cfg.CitadelDryRun, logger)
	go citadelClient.Run(ctx)
	if cfg.CitadelAPIURL != "" && len(cfg.CitadelHMACSecrets) == 0 {
		logger.Fatal().Msg("OPENCSIRT_CITADEL_HMAC_SECRETS required when CITADEL_API_URL is set")
	}

	if outboxStore != nil {
		watcher := citadel.NewWatcher(outboxStore, citadelClient, cfg.OutboxTickInterval, logger)
		go watcher.Run(ctx)
	}

	// ── Python advisory subsystem ──
	// BuildAdvisoryURL resolves the explicit URL (if set) or falls back
	// to OPENCSIRT_PY_HOST + OPENCSIRT_PY_PORT so Go and Python read the
	// same env vars for the service address.
	var pyClient advisory.PythonClient
	advisoryURL := advisory.BuildAdvisoryURL(cfg.AdvisoryServiceURL, cfg.AdvisoryPyHost, cfg.AdvisoryPyPort)
	if advisoryURL != "" {
		pyClient = advisory.NewHTTPClient(advisoryURL, cfg.AdvisoryServiceJWT)
	} else {
		pyClient = advisory.NoopClient{}
	}

	// ── Services ──
	var (
		constituencySvc *constituency.Service
		incidentSvc     *incident.Service
		advisorySvc     *advisory.Service
	)
	if pool != nil {
		constituencySvc = constituency.New(constituencyStore, auditStore, logger)
		incidentSvc = incident.New(incidentStore, outboxStore, auditStore, logger)
		advisorySvc = advisory.NewService(advisoryStore, outboxStore, auditStore, pyClient)
	}

	// ── Integrations ──
	nis2Client := integrations.NewNIS2Client(cfg.NIS2CompassAPIURL, logger)

	if cfg.ThreatFlowAPIURL != "" && iocIngestStore != nil {
		tfClient := integrations.NewThreatFlowClient(cfg.ThreatFlowAPIURL, cfg.ThreatFlowAPIKey, cfg.ThreatFlowInterval, iocIngestStore, logger)
		go tfClient.Run(ctx)
		if advisorySvc != nil {
			advisorySvc.ThreatFlow = tfClient
		}
	}

	var irflowWebhook http.Handler
	if cfg.IRFlowWebhookSecret != "" && incidentSvc != nil {
		irflowWebhook = integrations.NewIRFlowWebhook(integrations.IRFlowConfig{
			Secret:         cfg.IRFlowWebhookSecret,
			StrictSeverity: cfg.IRFlowStrictSeverity,
		}, incidentSvc, logger)
	}

	if cfg.VertGuardAPIURL != "" && incidentSvc != nil {
		vg := integrations.NewVertGuardSubscriber(cfg.VertGuardAPIURL, cfg.VertGuardAPIKey,
			func(ctx context.Context, advisoryID string, payload map[string]any) error {
				_, err := incidentSvc.Create(ctx, incident.CreateInput{
					Source:      "peer_csirt",
					Severity:    "medium",
					Title:       "VertGuard advisory: " + advisoryID,
					Description: "Cross-CSIRT AI-threat advisory",
					Metadata:    map[string]any{"vertguard_advisory_id": advisoryID, "payload": payload},
				}, uuid.Nil, "vertguard_subscriber")
				return err
			}, logger)
		go vg.Run(ctx)
	}

	// ── HTTP server ──
	deps := api.Deps{
		Auth:        authn,
		AuthHandler: &handlers.Auth{Authenticator: authn},
		Health:      &handlers.Health{Pool: pool, Advisory: pyClient.Health, StartedAt: time.Now()},
	}
	if pool != nil {
		deps.Snapshot = &handlers.Snapshot{
			Incidents:   incidentStore,
			Advisories:  advisoryStore,
			Outbox:      outboxStore,
			IOCIngest:   iocIngestStore,
			QueueDepth:  citadelClient.QueueDepth,
			HealthCheck: func(c context.Context) bool { return pyClient.Health(c) == nil },
			NodeName:    cfg.Node,
			Version:     version.Version,
		}
		deps.Constituency = &handlers.Constituency{Service: constituencySvc}
		deps.Incident = &handlers.Incident{Service: incidentSvc, NIS2: nis2Client}
		deps.Advisory = &handlers.Advisory{Service: advisorySvc}
		deps.Peers = &handlers.Peers{Store: peerStore}
	}
	deps.IRFlowWebhook = irflowWebhook

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.Router(deps),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info().Str("addr", cfg.HTTPAddr).Msg("opencsirt: listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal().Err(err).Msg("http server")
		}
	}()

	// ── Shutdown ──
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logger.Info().Msg("opencsirt: shutting down")

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer sCancel()
	_ = srv.Shutdown(shutdownCtx)
	cancel()
}

