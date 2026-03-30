package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version and GitCommit are exported so they can be set via ldflags from the
// build system:
//
//	go build -ldflags "-X github.com/opensecstack/tds-scanner/cmd.Version=1.2.3 \
//	                   -X github.com/opensecstack/tds-scanner/cmd.GitCommit=abc1234"
var (
	Version   = version
	GitCommit = gitCommit
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the tds-scanner version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("tds-scanner %s (commit %s)\n", Version, GitCommit)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
