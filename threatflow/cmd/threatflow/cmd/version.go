package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/opensecstack/threatflow/internal/version"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the ThreatFlow version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("threatflow %s (commit: %s, built: %s)\n",
			version.Version, version.GitCommit, version.BuildDate)
	},
}
