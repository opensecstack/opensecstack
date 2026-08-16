package main

import (
	"context"
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
		if err := checkHealth(cmd.Context(), client, addr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	healthCmd.Flags().String("addr", "localhost:8100", "host:port of the sinauth HTTP server")
}

// checkHealth issues GET http://<addr>/api/v1/health via client and reports
// an error unless the server responds 200 OK. Split out of healthCmd's RunE
// so the success/failure decision logic is unit-testable without going
// through os.Exit (which would kill the test process).
func checkHealth(ctx context.Context, client *http.Client, addr string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/api/v1/health", nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned %d", resp.StatusCode)
	}
	return nil
}
