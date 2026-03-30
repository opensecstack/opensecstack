// scan_and_report demonstrates the full APIGuard scan lifecycle using the
// opensecstack Go SDK:
//
//  1. Create an APIGuardClient with retry options.
//  2. Start a scan against a publicly reachable OpenAPI spec.
//  3. Poll until the scan reaches "completed" or "failed".
//  4. Stream the JSON report directly to a file (no full in-memory buffer).
//  5. List findings and print a severity summary.
//
// Prerequisites:
//
//	go run ./sdk/examples/go/scan_and_report
//
// Required environment variables:
//
//	APIGUARD_URL        Base URL of your APIGuard instance, e.g. https://apiguard.example.com
//	APIGUARD_API_KEY    API key issued by the platform
//
// Optional environment variables:
//
//	APIGUARD_SPEC_URL   OpenAPI spec URL to scan (default: https://petstore3.swagger.io/api/v3/openapi.json)
//	APIGUARD_TARGET     Target base URL (default: derived from spec URL host)
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	opensecstack "github.com/opensecstack/sdk/opensecstack"
)

func main() {
	// ------------------------------------------------------------------
	// 1. Build the client with retry options.
	// ------------------------------------------------------------------
	baseURL := requireEnv("APIGUARD_URL")
	apiKey := requireEnv("APIGUARD_API_KEY")

	client := opensecstack.NewAPIGuardClient(baseURL, apiKey)
	// Retry up to 3 times on transient 5xx errors, starting with a 500 ms
	// back-off that doubles on each attempt (500 ms → 1 s → 2 s).
	client.MaxRetries = 3
	client.RetryWaitBase = 500 * time.Millisecond
	// Allow up to 3 minutes to generate the final report.
	client.ReportTimeout = 3 * time.Minute

	// ------------------------------------------------------------------
	// 2. Start the scan.
	// ------------------------------------------------------------------
	specURL := envOrDefault(
		"APIGUARD_SPEC_URL",
		"https://petstore3.swagger.io/api/v3/openapi.json",
	)
	target := os.Getenv("APIGUARD_TARGET") // empty → SDK derives from spec host

	ctx := context.Background()

	log.Printf("Starting scan: spec=%s target=%q", specURL, target)
	scan, err := client.CreateScanFull(ctx, opensecstack.CreateScanOptions{
		SpecURL: specURL,
		Target:  target,
	})
	if err != nil {
		log.Fatalf("CreateScan: %v", err)
	}
	log.Printf("Scan created: id=%s status=%s", scan.ID, scan.Status)

	// ------------------------------------------------------------------
	// 3. Poll until completion (or timeout after 10 minutes).
	// ------------------------------------------------------------------
	pollCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	scan, err = waitForScan(pollCtx, client, scan.ID)
	if err != nil {
		log.Fatalf("polling scan: %v", err)
	}
	if scan.Status == opensecstack.ScanStatusFailed {
		log.Fatalf("Scan %s failed: %s", scan.ID, scan.ErrorMessage)
	}
	log.Printf("Scan %s completed: total_findings=%d", scan.ID, scan.TotalFindings)

	// ------------------------------------------------------------------
	// 4. Stream the JSON report to a local file.
	// ------------------------------------------------------------------
	reportFile := fmt.Sprintf("report-%s.json", scan.ID)
	f, err := os.Create(reportFile)
	if err != nil {
		log.Fatalf("creating report file: %v", err)
	}
	defer f.Close()

	log.Printf("Streaming JSON report to %s …", reportFile)
	streamCtx, streamCancel := context.WithTimeout(ctx, client.ReportTimeout)
	defer streamCancel()

	if err := client.GetReportStream(streamCtx, scan.ID, "json", f); err != nil {
		log.Fatalf("GetReportStream: %v", err)
	}
	log.Printf("Report written to %s", reportFile)

	// ------------------------------------------------------------------
	// 5. List findings and print a severity summary.
	// ------------------------------------------------------------------
	findings, err := client.GetFindings(ctx, scan.ID, opensecstack.GetFindingsOptions{
		PerPage: 100,
	})
	if err != nil {
		log.Fatalf("GetFindings: %v", err)
	}

	counts := map[opensecstack.FindingSeverity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Println("\n--- Findings summary ---")
	fmt.Printf("  critical : %d\n", counts[opensecstack.FindingSeverityCritical])
	fmt.Printf("  high     : %d\n", counts[opensecstack.FindingSeverityHigh])
	fmt.Printf("  medium   : %d\n", counts[opensecstack.FindingSeverityMedium])
	fmt.Printf("  low      : %d\n", counts[opensecstack.FindingSeverityLow])
	fmt.Printf("  info     : %d\n", counts[opensecstack.FindingSeverityInfo])
	fmt.Printf("  total    : %d\n", len(findings))
}

// waitForScan polls GET /api/v1/scans/{id} every 5 seconds until the scan
// reaches a terminal state ("completed", "failed", "cancelled") or the
// context deadline is exceeded.
func waitForScan(ctx context.Context, client *opensecstack.APIGuardClient, scanID string) (*opensecstack.Scan, error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for scan %s: %w", scanID, ctx.Err())
		case <-ticker.C:
			scan, err := client.GetScan(ctx, scanID)
			if err != nil {
				log.Printf("GetScan warning: %v (will retry)", err)
				continue
			}
			log.Printf("Scan %s status: %s", scanID, scan.Status)
			switch scan.Status {
			case opensecstack.ScanStatusCompleted,
				opensecstack.ScanStatusFailed,
				opensecstack.ScanStatusCancelled:
				return scan, nil
			}
		}
	}
}

// requireEnv returns the value of an environment variable or terminates the
// process with a helpful message if the variable is unset or empty.
func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return v
}

// envOrDefault returns the value of an environment variable or a fallback
// default value when the variable is unset or empty.
func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
