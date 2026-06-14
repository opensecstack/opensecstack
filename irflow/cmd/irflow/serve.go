package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/api"
	"github.com/opensecstack/opensecstack/irflow/internal/auth"
	"github.com/opensecstack/opensecstack/irflow/internal/config"
	"github.com/opensecstack/opensecstack/irflow/internal/db"
	"github.com/opensecstack/opensecstack/irflow/internal/governance"
	"github.com/opensecstack/opensecstack/irflow/internal/incident"
	"github.com/opensecstack/opensecstack/irflow/internal/metrics"
	"github.com/opensecstack/opensecstack/irflow/internal/playbook"
	"github.com/opensecstack/opensecstack/irflow/internal/version"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the IRFlow HTTP server",
	RunE:  runServe,
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("initialising logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()

	logger.Info("irflow starting",
		zap.String("version", version.Version),
		zap.String("commit", version.GitCommit),
		zap.String("built", version.BuildDate),
	)

	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelConnect()

	pool, err := db.NewPool(connectCtx,
		cfg.DB.Host, cfg.DB.Port, cfg.DB.Name,
		cfg.DB.User, cfg.DB.Password, cfg.DB.SSLMode,
	)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pool.Close()
	logger.Info("database connected", zap.String("host", cfg.DB.Host), zap.Int("port", cfg.DB.Port))

	mx := metrics.New(nil)
	logger.Info("metrics registered — /metrics endpoint live")

	// Periodically refresh DB-pool gauges. Cheap, bounded, stopped on shutdown.
	poolStatsStop := make(chan struct{})
	go func() {
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-poolStatsStop:
				return
			case <-tick.C:
				st := pool.Stat()
				mx.SetDBPoolStats(st.AcquiredConns(), st.IdleConns(), st.MaxConns())
			}
		}
	}()
	defer close(poolStatsStop)

	incidentStore := db.NewPGStore(pool)

	incidentOpts := []incident.ServiceOption{
		incident.WithLogger(logger),
		incident.WithMetrics(mx),
	}
	if cfg.Citadel.APIURL != "" && cfg.Citadel.KeySecret != "" {
		citadelClient := governance.NewCitadelClient(governance.CitadelClientConfig{
			BaseURL:   cfg.Citadel.APIURL,
			KeyID:     cfg.Citadel.KeyID,
			KeySecret: cfg.Citadel.KeySecret,
			ProjectID: cfg.Citadel.ProjectID,
			DryRun:    cfg.Citadel.DryRun,
		})
		incidentOpts = append(incidentOpts,
			incident.WithMarshal(citadelClient),
			incident.WithWORM(citadelClient),
		)
		logger.Info("citadel integration enabled",
			zap.String("base_url", cfg.Citadel.APIURL),
			zap.Bool("dry_run", cfg.Citadel.DryRun))
	} else {
		logger.Warn("citadel integration disabled (CITADEL_API_URL or CITADEL_KEY_SECRET not set) — actions run without MARSHAL and events are not anchored in WORM")
	}
	if cfg.NIS2.APIURL != "" && cfg.NIS2.APIKey != "" && cfg.NIS2.AssessmentID != "" {
		nis2Client := governance.NewNIS2Client(governance.NIS2ClientConfig{
			BaseURL:      cfg.NIS2.APIURL,
			APIKey:       cfg.NIS2.APIKey,
			AssessmentID: cfg.NIS2.AssessmentID,
			MeasureRef:   cfg.NIS2.MeasureRef,
		})
		incidentOpts = append(incidentOpts, incident.WithNIS2(nis2Client))
		logger.Info("nis2 compass integration enabled",
			zap.String("assessment_id", cfg.NIS2.AssessmentID),
			zap.String("measure_ref", cfg.NIS2.MeasureRef))
	} else {
		logger.Warn("nis2 compass integration disabled — regulatory-significant incidents will not be notified automatically")
	}
	incidentSvc := incident.NewService(incidentStore, incidentOpts...)

	playbookStore := db.NewPGPlaybookStore(pool)
	executor := playbook.NewExecutor(logger)
	playbookSvc := playbook.NewService(playbookStore, executor, logger).WithMetrics(mx)

	sinauthURL := cfg.Auth.SinauthURL
	if sinauthURL == "" {
		sinauthURL = "http://localhost:8100"
	}
	authCfg := auth.Config{
		Secret:     cfg.Auth.Secret,
		Disabled:   cfg.Auth.DevMode,
		Pepper:     cfg.Auth.Pepper,
		SinauthURL: sinauthURL,
		Logger:     logger,
	}
	// Don't construct the hasher eagerly — callers that need it (future
	// API-key module) invoke auth.NewHasher(authCfg) at their own init time
	// and surface configuration errors there.
	if cfg.Auth.Pepper != "" {
		logger.Info("auth: password pepper configured — Argon2id hasher available via auth.NewHasher")
	} else {
		logger.Warn("auth: password pepper not configured (IRFLOW_AUTH_PEPPER empty); API-key hashing will fail at init time if any feature needs it")
	}
	if authCfg.Secret == "" && !authCfg.Disabled {
		logger.Warn("auth: signing secret not configured; enabling dev mode. NEVER USE IN PRODUCTION")
		authCfg.Disabled = true
	}
	if authCfg.Disabled {
		logger.Warn("auth: middleware is DISABLED (dev mode) — all API routes are open")
	} else {
		logger.Info("auth: JWT enforcement enabled",
			zap.String("issuer", cfg.Auth.Issuer),
			zap.Duration("token_ttl", cfg.Auth.TokenTTL))
	}

	srv := api.NewServer(api.Options{
		Logger:    logger,
		Incidents: incidentSvc,
		Playbooks: playbookSvc,
		Pinger:    &poolPinger{pool: pool},
		Webhooks: api.WebhookSecrets{
			APIGuard:    cfg.Webhook.ResolvedSecret("apiguard"),
			CITADEL:     cfg.Webhook.ResolvedSecret("citadel"),
			ThreatFlow:  cfg.Webhook.ResolvedSecret("threatflow"),
			MaxBodySize: cfg.Webhook.MaxBodySize,
			ClockSkew:   cfg.Webhook.ClockSkewTolerance,
		},
		Auth:    authCfg,
		Metrics: mx,
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      srv,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("irflow listening", zap.String("addr", addr))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		close(serveErr)
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		stop()
		logger.Info("shutdown signal received — draining connections")
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		logger.Info("irflow stopped cleanly")
		return nil
	}
}

// poolPinger adapts *pgxpool.Pool to the api.Pinger interface without exposing
// database types to the api package.
type poolPinger struct {
	pool interface {
		Ping(ctx context.Context) error
	}
}

func (p *poolPinger) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}
