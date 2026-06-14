package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage signing keys",
}

var keysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new RSA-2048 signing key pair",
	RunE:  runKeysGenerate,
}

var keysRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the active signing key",
	RunE:  runKeysRotate,
}

func init() {
	keysCmd.AddCommand(keysGenerateCmd)
	keysCmd.AddCommand(keysRotateCmd)
}

func runKeysGenerate(cmd *cobra.Command, args []string) error {
	fmt.Println("Generated key pair — not yet implemented")
	return nil
}

func runKeysRotate(cmd *cobra.Command, args []string) error {
	fmt.Println("Key rotation — not yet implemented")
	return nil
}
