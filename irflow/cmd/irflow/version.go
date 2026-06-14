package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/opensecstack/opensecstack/irflow/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the IRFlow version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("irflow %s (commit: %s, built: %s)\n",
			version.Version, version.GitCommit, version.BuildDate)
	},
}
