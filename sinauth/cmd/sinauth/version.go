package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version, Commit, and Date are set at build time via ldflags:
//
//	-X github.com/opensecstack/sinauth/cmd/sinauth.Version=<ver>
//	-X github.com/opensecstack/sinauth/cmd/sinauth.Commit=<sha>
//	-X github.com/opensecstack/sinauth/cmd/sinauth.Date=<date>
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("sinauth %s (%s %s)\n", Version, Commit, Date)
	},
}
