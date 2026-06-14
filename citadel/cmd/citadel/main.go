package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/citadel/internal/api"
	"github.com/opensecstack/citadel/internal/config"
	"github.com/opensecstack/citadel/internal/db"
	"github.com/opensecstack/citadel/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("citadel %s (commit: %s, built: %s)\n",
			version.Version, version.GitCommit, version.BuildDate)
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

	// Start HTTP server.
	srv := api.NewServer(cfg, database)
	if err := srv.Start(); err != nil {
		log.Fatalf("citadel: server error: %v", err)
	}
}
