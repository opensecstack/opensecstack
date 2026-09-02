package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/citadel/internal/api"
	"github.com/opensecstack/citadel/internal/config"
	"github.com/opensecstack/citadel/internal/db"
	"github.com/opensecstack/citadel/internal/keygen"
	"github.com/opensecstack/citadel/internal/permifysync"
	"github.com/opensecstack/citadel/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("citadel %s (commit: %s, built: %s)\n",
			version.Version, version.GitCommit, version.BuildDate)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		if err := keygen.Run(os.Args[2:], os.Stdout); err != nil {
			log.Fatalf("citadel keygen: %v", err)
		}
		return
	}

	cfg := config.Load()
	cfg.WarnIfInsecure()

	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().
		Timestamp().
		Str("service", "citadel").
		Logger()

	logger.Info().
		Str("version", version.Version).
		Str("commit", version.GitCommit).
		Str("built", version.BuildDate).
		Int("port", cfg.Port).
		Str("log_level", cfg.LogLevel).
		Msg("CITADEL governance engine starting")

	// Connect to PostgreSQL.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	database, err := db.New(ctx, cfg.DB.URL)
	if err != nil {
		log.Fatalf("citadel: database connection failed: %v", err)
	}
	defer database.Close()

	logger.Info().Msg("database connection established")

	// Wire the Ed25519 master key + anchor interval into the DB layer so
	// AppendWORM can produce anchors and VerifyChain can check them (see
	// internal/db/worm.go's ConfigureAnchoring). A malformed (non-empty but
	// invalid) key is a config error and must fail startup loudly rather
	// than silently disabling anchoring — an empty key is the documented,
	// already-warned-about "anchoring disabled" case (WarnIfInsecure above).
	if err := database.ConfigureAnchoring(cfg.Citadel.MasterKey, cfg.Citadel.AnchorInterval); err != nil {
		log.Fatalf("citadel: %v", err)
	}

	// Start the Permify-snapshot background sync (internal/permifysync) —
	// only when a Permify endpoint is configured. This is what Gate 2's
	// EnforcePermifyAuthz check reads from; see
	// adrs/007-permify-gate2-snapshot.md. Follows the same
	// signal.NotifyContext graceful-shutdown convention Server.Start uses
	// for the HTTP server below — the two goroutines shut down
	// independently on the same OS signal.
	var permifySnapshot *permifysync.Snapshot
	if cfg.Citadel.PermifyURL != "" {
		permifySnapshot = permifysync.NewSnapshot()

		interval := cfg.Citadel.PermifySyncInterval
		if interval <= 0 {
			interval = 5 * time.Minute
		}

		fetcher := permifysync.NewPermifyFetcher(cfg.Citadel.PermifyURL, 5*time.Second, logger)
		store := permifysync.NewPgSnapshotStore(database.Pool)
		syncer := permifysync.New(fetcher, store, permifySnapshot, interval, logger)

		syncCtx, syncStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer syncStop()

		loadCtx, loadCancel := context.WithTimeout(syncCtx, 15*time.Second)
		if err := syncer.LoadInitial(loadCtx); err != nil {
			logger.Warn().Err(err).Msg("citadel: permifysync initial snapshot load failed — starting from an empty snapshot")
		}
		loadCancel()

		go syncer.Run(syncCtx)
		logger.Info().
			Str("permify_url", cfg.Citadel.PermifyURL).
			Dur("interval", interval).
			Msg("permifysync: background sync started")
	} else {
		logger.Info().Msg("permifysync: CITADEL_PERMIFY_URL not set — Gate 2 Permify-snapshot check stays disabled (rbacMap-only)")
	}

	// Start HTTP server.
	srv, err := api.NewServer(cfg, database, permifySnapshot)
	if err != nil {
		log.Fatalf("citadel: server init failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		log.Fatalf("citadel: server error: %v", err)
	}
}
