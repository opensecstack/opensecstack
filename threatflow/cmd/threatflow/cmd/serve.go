package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/opensecstack/threatflow/internal/api"
	"github.com/opensecstack/threatflow/internal/auth"
	"github.com/opensecstack/threatflow/internal/cache"
	"github.com/opensecstack/threatflow/internal/citadel"
	"github.com/opensecstack/threatflow/internal/config"
	"github.com/opensecstack/threatflow/internal/db"
	"github.com/opensecstack/threatflow/internal/db/store"
	"github.com/opensecstack/threatflow/internal/feed"
)

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().Int("port", 8091, "HTTP listen port")
	viper.BindPFlag("port", serveCmd.Flags().Lookup("port"))
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the ThreatFlow HTTP API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()

		startCtx := context.Background()
		database, err := db.Open(startCtx, cfg.DB)
		if err != nil {
			log.Warn().Err(err).Msg("database unavailable — starting without persistence")
			database = nil
		} else {
			defer database.Close()
			log.Info().Msg("database connected")
		}

		failMode := citadel.FailOpen
		if cfg.Citadel.FailClosed {
			failMode = citadel.FailClosed
		}
		citadelClient := citadel.New(citadel.Config{
			BaseURL:   cfg.Citadel.APIURL,
			KeyID:     cfg.Citadel.KeyID,
			Secret:    cfg.Citadel.KeySecret,
			ProjectID: cfg.Citadel.ProjectID,
			FailMode:  failMode,
		}, log.Logger)
		if citadelClient.Enabled() {
			log.Info().Str("url", cfg.Citadel.APIURL).Bool("fail_closed", cfg.Citadel.FailClosed).Msg("citadel governance enabled")
		} else {
			log.Info().Msg("citadel governance disabled (no api url)")
		}

		var apiKeyStore *store.APIKeyStore
		if database != nil {
			apiKeyStore = store.NewAPIKeyStore(database.Pool)
		}
		bootstrap := map[string]auth.Role{}
		for _, k := range cfg.Auth.BootstrapKeys {
			if k != "" {
				bootstrap[k] = auth.RoleAdmin
			}
		}
		authSvc, err := auth.NewService(auth.Config{
			Secret:        cfg.Auth.JWTSecret,
			TTL:           time.Duration(cfg.Auth.TTLMinutes) * time.Minute,
			APIKeys:       apiKeyStore,
			BootstrapKeys: bootstrap,
		})
		if err != nil {
			return fmt.Errorf("init auth: %w", err)
		}
		if cfg.Auth.JWTSecret == "" && len(bootstrap) == 0 && apiKeyStore == nil {
			log.Warn().Msg("auth secret generated ephemerally AND no keys configured — mutation routes are unprotected")
		}

		redisCtx, redisCancel := context.WithTimeout(startCtx, 5*time.Second)
		redisCache, err := cache.Open(redisCtx, cfg.Cache.RedisURL, time.Duration(cfg.Cache.TTLSeconds)*time.Second, log.Logger)
		redisCancel()
		if err != nil {
			log.Warn().Err(err).Msg("redis unavailable — starting without cache")
			redisCache, _ = cache.Open(context.Background(), "", 0, log.Logger)
		}
		defer redisCache.Close()
		if redisCache.Enabled() {
			log.Info().Str("url", cfg.Cache.RedisURL).Msg("redis cache enabled")
		}

		srv := api.NewServer(cfg, database, citadelClient, authSvc, redisCache)

		var scheduler *feed.Scheduler
		if database != nil && srv.Importer != nil && srv.Feeds != nil {
			scheduler = feed.NewScheduler(srv.Feeds, srv.Importer, log.Logger)
			scheduler.Start(startCtx)
		}

		addr := fmt.Sprintf(":%d", cfg.Port)
		httpServer := &http.Server{
			Addr:         addr,
			Handler:      srv.Router(),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		// Graceful shutdown on SIGINT/SIGTERM.
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			log.Info().Str("addr", addr).Msg("ThreatFlow API server starting")
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("server failed")
			}
		}()

		<-quit
		log.Info().Msg("shutting down…")

		if scheduler != nil {
			scheduler.Stop()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Drain in-flight WORM emissions + webhook deliveries before closing
		// the HTTP listener so the final audit events reach CITADEL and all
		// registered ecosystem subscribers.
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Second)
		citadelClient.Drain(drainCtx)
		if srv.Dispatcher != nil {
			srv.Dispatcher.Drain(drainCtx)
		}
		drainCancel()

		return httpServer.Shutdown(ctx)
	},
}
