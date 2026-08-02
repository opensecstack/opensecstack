package cmd

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/opensecstack/threatflow/internal/config"
	"github.com/opensecstack/threatflow/internal/db"
)

var (
	migrateRollback int
	migrateTarget   int
	migrateStatus   bool
	migrateForce    int
)

func init() {
	rootCmd.AddCommand(migrateCmd)
	migrateCmd.Flags().IntVar(&migrateRollback, "rollback", 0, "Roll back N migrations (0 = apply up)")
	migrateCmd.Flags().IntVar(&migrateTarget, "target", -1, "Migrate to a specific version")
	migrateCmd.Flags().BoolVar(&migrateStatus, "status", false, "Print current schema version and exit")
	migrateCmd.Flags().IntVar(&migrateForce, "force", -1, "Force version without running migrations (recovery only)")
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Apply, roll back, or inspect database migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()
		mg, err := db.NewMigrator(cfg.DB.URL)
		if err != nil {
			return fmt.Errorf("migrator: %w", err)
		}
		defer mg.Close()

		switch {
		case migrateStatus:
			v, dirty, err := mg.Status()
			if err != nil {
				return err
			}
			state := "clean"
			if dirty {
				state = "DIRTY"
			}
			fmt.Printf("version: %d (%s)\n", v, state)
			return nil

		case migrateForce >= 0:
			log.Warn().Int("version", migrateForce).Msg("forcing schema version — recovery mode")
			return mg.Force(migrateForce)

		case migrateTarget >= 0:
			log.Info().Int("target", migrateTarget).Msg("migrating to target version")
			return mg.Target(uint(migrateTarget))

		case migrateRollback > 0:
			log.Info().Int("steps", migrateRollback).Msg("rolling back migrations")
			return mg.Down(migrateRollback)

		default:
			log.Info().Msg("applying pending migrations")
			if err := mg.Up(); err != nil {
				return err
			}
			v, _, _ := mg.Status()
			log.Info().Uint("version", v).Msg("migrations applied")
			return nil
		}
	},
}
