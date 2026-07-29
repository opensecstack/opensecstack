package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/sinauth/internal/api"
	"github.com/opensecstack/sinauth/internal/config"
	"github.com/opensecstack/sinauth/internal/keys"
	"github.com/opensecstack/sinauth/internal/user"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the sinauth HTTP server",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().String("addr", "", "HTTP listen address (overrides SINAUTH_HTTP_ADDR)")
}

func runServe(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if addr, _ := cmd.Flags().GetString("addr"); addr != "" {
		cfg.HTTPAddr = addr
	}

	// Key manager
	km := keys.New(cfg.SigningKeyID)
	keyPath := cfg.SigningKeyPath
	if keyPath == "" {
		keyPath = "dev-keys/sinauth.pem"
	}
	if err := km.LoadOrGenerate(keyPath); err != nil {
		return fmt.Errorf("keys: %w", err)
	}

	// Database
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("db ping: %w", err)
	}
	log.Println("sinauth: database connected")

	// Bootstrap the first platform admin, if configured. See SECURITY.md.
	if cfg.BootstrapAdminEmail != "" {
		store := user.NewStore(pool)
		promoted, err := store.SetPlatformAdmin(ctx, cfg.BootstrapAdminEmail, true)
		if err != nil {
			log.Printf("sinauth: WARNING: failed to bootstrap platform admin %q: %v", cfg.BootstrapAdminEmail, err)
		} else if promoted {
			log.Printf("sinauth: bootstrapped platform admin: %s", cfg.BootstrapAdminEmail)
		} else {
			log.Printf("sinauth: SINAUTH_BOOTSTRAP_ADMIN_EMAIL=%s set but no matching user exists yet — "+
				"register that account, then restart sinauth (or re-run) to promote it", cfg.BootstrapAdminEmail)
		}
	}

	handler := api.NewServer(cfg, pool, km)

	srv := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("sinauth: listening on %s", cfg.HTTPAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// devMode checks if SINAUTH_DEV_MODE is set.
func devMode() bool {
	return os.Getenv("SINAUTH_DEV_MODE") == "true"
}
