package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "irflow",
	Short: "IRFlow — Incident Response Workflow Engine",
	Long: `IRFlow is the incident response workflow engine for the OpenSecStack
ecosystem. It manages the full incident lifecycle — from detection through
containment, eradication, recovery, and closure — with CITADEL governance
and NIS2 Art. 23 compliance built in.`,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(authCmd)
}
