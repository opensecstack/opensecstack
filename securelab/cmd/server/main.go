// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Command server starts the SecureLab HTTP API server.
//
// Configuration is read entirely from environment variables prefixed with
// SECURELAB_. See internal/config for the full list of supported variables.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/opensecstack/securelab/internal/api"
	"github.com/opensecstack/securelab/internal/attacks/dispatch"
	"github.com/opensecstack/securelab/internal/citadel"
	"github.com/opensecstack/securelab/internal/config"
	dbpkg "github.com/opensecstack/securelab/internal/db"
	"github.com/opensecstack/securelab/internal/db/migrations"
	"github.com/opensecstack/securelab/internal/detection"
	"github.com/opensecstack/securelab/internal/scenarios"
	"github.com/opensecstack/securelab/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("securelab %s (commit: %s, built: %s)\n",
			version.Version, version.GitCommit, version.BuildDate)
		return
	}

	log, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "securelab: init logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck

	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatal("load config", zap.Error(err))
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal("invalid config", zap.Error(err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := dbpkg.New(ctx, cfg)
	if err != nil {
		log.Fatal("open db pool", zap.Error(err))
	}
	defer pool.Close()

	if err := runMigrations(ctx, pool, log); err != nil {
		log.Fatal("run migrations", zap.Error(err))
	}

	// The monitor is wired to real detection platforms via environment variables.
	dispatcher := dispatch.NewDispatcher()
	detMonitor := detection.NewMonitor(
		os.Getenv("SECURELAB_OPENSCRUB_URL"),
		os.Getenv("SECURELAB_APIGUARD_URL"),
		os.Getenv("SECURELAB_THREATFLOW_URL"),
	)
	monitor := scenarios.NewMonitorAdapter(detMonitor)

	executor := scenarios.NewExecutor(pool, dispatcher, monitor, log)
	if cfg.CitadelAPIURL != "" && !cfg.CitadelDryRun {
		secret := ""
		if len(cfg.CitadelHMACSecrets) > 0 {
			secret = cfg.CitadelHMACSecrets[0]
		}
		citConn := citadel.NewConnector(cfg.CitadelAPIURL, secret)
		executor.WithCitadel(citConn)
		log.Info("Citadel event forwarding enabled", zap.String("url", cfg.CitadelAPIURL))
	} else if cfg.CitadelAPIURL != "" {
		log.Info("Citadel dry-run mode — events will not be forwarded")
	}
	scheduler, err := scenarios.NewScheduler(cfg.MaxConcurrentScenarios, executor, log)
	if err != nil {
		log.Fatal("create scheduler", zap.Error(err))
	}

	startTime := time.Now()
	router := api.NewRouter(pool, scheduler, cfg.JWTSecret, cfg.SinauthURL, startTime, log)

	srv := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("SecureLab server starting",
			zap.String("addr", cfg.HTTPAddr),
			zap.String("version", version.Version),
			zap.String("commit", version.GitCommit),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		log.Fatal("server error", zap.Error(err))
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Error("graceful shutdown failed", zap.Error(err))
	}
	log.Info("server stopped")
}

// sqlExecer is the minimal subset of *pgxpool.Pool that runMigrations needs.
// Extracting it as an interface lets tests exercise runMigrations' file
// discovery, ordering, and error-handling logic with a fake, without a live
// database connection.
type sqlExecer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// runMigrations executes every *.sql file from the embedded migrations FS in
// lexicographic (numeric-prefix) order. DDL uses IF NOT EXISTS guards so
// repeated server starts are idempotent.
func runMigrations(ctx context.Context, pool sqlExecer, log *zap.Logger) error {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("migrations: read embedded dir: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		data, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("migrations: read %s: %w", name, err)
		}
		log.Info("applying migration", zap.String("file", name))
		if _, err := pool.Exec(ctx, string(data)); err != nil {
			return fmt.Errorf("migrations: exec %s: %w", name, err)
		}
	}
	return nil
}
