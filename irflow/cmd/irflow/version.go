package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the IRFlow version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("irflow %s\n", version)
	},
}
