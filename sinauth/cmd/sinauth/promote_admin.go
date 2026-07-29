package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/sinauth/internal/config"
	"github.com/opensecstack/sinauth/internal/user"
	"github.com/spf13/cobra"
)

// promoteAdminCmd is the one-off CLI path for bootstrapping (or revoking)
// platform-admin standing for a user, as an alternative to setting
// SINAUTH_BOOTSTRAP_ADMIN_EMAIL and restarting `sinauth serve`. See
// SECURITY.md for the full bootstrap procedure.
var promoteAdminCmd = &cobra.Command{
	Use:   "promote-admin <email>",
	Short: "Grant (or revoke with --revoke) platform-admin standing to a user by email",
	Args:  cobra.ExactArgs(1),
	RunE:  runPromoteAdmin,
}

func init() {
	promoteAdminCmd.Flags().Bool("revoke", false, "revoke platform-admin standing instead of granting it")
}

func runPromoteAdmin(cmd *cobra.Command, args []string) error {
	email := args[0]
	revoke, _ := cmd.Flags().GetBool("revoke")

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("db ping: %w", err)
	}

	store := user.NewStore(pool)
	found, err := store.SetPlatformAdmin(ctx, email, !revoke)
	if err != nil {
		return fmt.Errorf("set platform admin: %w", err)
	}
	if !found {
		return fmt.Errorf("no user with email %q found", email)
	}

	if revoke {
		fmt.Printf("sinauth: revoked platform-admin standing from %s\n", email)
	} else {
		fmt.Printf("sinauth: granted platform-admin standing to %s\n", email)
	}
	return nil
}
