package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Populated via -ldflags at build time.
var (
	version   = "1.0.0"
	gitCommit = "unknown"
)

var (
	flagFormat   string
	flagOutput   string
	flagSeverity string
)

var rootCmd = &cobra.Command{
	Use:   "tds-scanner",
	Short: "Scan OpenSecStack SDK integrations for TDS compliance issues",
	Long: `tds-scanner analyses source code for Trust, Dependency, and Security (TDS)
compliance issues such as hardcoded credentials, disabled TLS verification,
missing retry logic, exposed secrets, and absent security headers.`,
	SilenceUsage: true,
}

// Execute is the entry point called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagFormat, "format", "text",
		`Output format: "text" or "json"`)
	rootCmd.PersistentFlags().StringVarP(&flagOutput, "output", "o", "",
		"Write output to this file path instead of stdout")
	rootCmd.PersistentFlags().StringVar(&flagSeverity, "severity", "low",
		`Minimum severity to report: "info", "low", "medium", "high", or "critical"`)
}
