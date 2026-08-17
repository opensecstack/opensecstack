package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/opensecstack/sinauth/internal/api"
	"github.com/opensecstack/sinauth/internal/config"
	"github.com/opensecstack/sinauth/internal/keys"
	"github.com/opensecstack/sinauth/internal/user"
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
	keyPath := resolveKeyPath(cfg.SigningKeyPath)
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
		log.Print(bootstrapAdminMessage(cfg.BootstrapAdminEmail, promoted, err))
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

// resolveKeyPath returns the configured signing key path, falling back to
// the dev-mode default when unset. Extracted from runServe so the fallback
// decision is unit-testable without touching the filesystem or DB.
func resolveKeyPath(configured string) string {
	if configured == "" {
		return "dev-keys/sinauth.pem"
	}
	return configured
}

// bootstrapAdminMessage renders the single log line runServe emits after
// attempting to bootstrap the configured platform-admin email, covering
// the three possible outcomes (store error, promoted, no matching user
// yet). Split out of runServe so the message-selection logic — which
// email/outcome maps to which of the three operator-facing messages — is
// unit-testable without a live DB.
func bootstrapAdminMessage(email string, promoted bool, err error) string {
	switch {
	case err != nil:
		return fmt.Sprintf("sinauth: WARNING: failed to bootstrap platform admin %q: %v", email, err)
	case promoted:
		return fmt.Sprintf("sinauth: bootstrapped platform admin: %s", email)
	default:
		return fmt.Sprintf("sinauth: SINAUTH_BOOTSTRAP_ADMIN_EMAIL=%s set but no matching user exists yet — "+
			"register that account, then restart sinauth (or re-run) to promote it", email)
	}
}
