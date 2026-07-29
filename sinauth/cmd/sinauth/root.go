package main

import (
	"github.com/spf13/cobra"
)

var root = &cobra.Command{
	Use:   "sinauth",
	Short: "SIN Identity Provider",
}

func init() {
	root.AddCommand(serveCmd)
	root.AddCommand(migrateCmd)
	root.AddCommand(keysCmd)
	root.AddCommand(versionCmd)
	root.AddCommand(healthCmd)
	root.AddCommand(promoteAdminCmd)
	root.AddCommand(permifySyncCmd)
}
