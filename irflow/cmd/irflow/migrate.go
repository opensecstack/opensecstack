package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	RunE:  runMigrate,
}

func runMigrate(cmd *cobra.Command, args []string) error {
	// TODO: read config, connect to DB, apply migrations from migrations/ dir
	fmt.Println("migrate: not yet implemented — apply migrations/001_initial.sql manually or via a migration tool")
	return nil
}
