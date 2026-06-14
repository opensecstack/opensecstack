package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check if the sinauth server is healthy (exits 0=ok, 1=unhealthy)",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")
		client := &http.Client{Timeout: 4 * time.Second}
		resp, err := client.Get("http://" + addr + "/api/v1/health")
		if err != nil {
			fmt.Fprintf(os.Stderr, "health check failed: %v\n", err)
			os.Exit(1)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "health check returned %d\n", resp.StatusCode)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	healthCmd.Flags().String("addr", "localhost:8100", "host:port of the sinauth HTTP server")
}
