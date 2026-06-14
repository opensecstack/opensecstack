// nis2_assessment demonstrates the NIS2 Compass assessment workflow using the
// opensecstack Go SDK:
//
//  1. Create a NIS2CompassClient.
//  2. Register a new organisation.
//  3. Create an assessment under that organisation.
//  4. Stream the SARIF report to a local file.
//
// Prerequisites:
//
//	go run ./sdk/examples/go/nis2_assessment
//
// Required environment variables:
//
//	NIS2_URL        Base URL of your NIS2 Compass instance, e.g. https://nis2.example.com
//	NIS2_API_KEY    API key issued by the platform
//
// Optional environment variables:
//
//	NIS2_ORG_NAME   Organisation display name (default: "Example Organisation")
//	NIS2_ORG_COUNTRY ISO 3166-1 alpha-2 country code (default: "DE")
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
	// 1. Build the NIS2 Compass client.
	// ------------------------------------------------------------------
	baseURL := requireEnv("NIS2_URL")
	apiKey := requireEnv("NIS2_API_KEY")

	client := opensecstack.NewNIS2CompassClient(baseURL, apiKey)
	// Retry up to 3 times on transient 5xx errors.
	client.MaxRetries = 3
	client.RetryWaitBase = 500 * time.Millisecond

	ctx := context.Background()

	// ------------------------------------------------------------------
	// 2. Register a new organisation.
	// ------------------------------------------------------------------
	orgName := envOrDefault("NIS2_ORG_NAME", "Example Organisation")
	orgCountry := envOrDefault("NIS2_ORG_COUNTRY", "DE")

	log.Printf("Creating organisation: name=%q country=%s", orgName, orgCountry)
	org, err := client.CreateOrganisation(ctx, opensecstack.CreateOrganisationRequest{
		Name:       orgName,
		Industry:   "Technology",
		Country:    orgCountry,
		Size:       "medium",
		EntityType: "important",
	})
	if err != nil {
		log.Fatalf("CreateOrganisation: %v", err)
	}
	log.Printf("Organisation created: id=%s name=%s", org.ID, org.Name)

	// ------------------------------------------------------------------
	// 3. Create an assessment under the organisation.
	//
	// The server automatically seeds 10 control entries (NIS2 Article 21(2)
	// measures a–j) when a new assessment is created.
	// ------------------------------------------------------------------
	log.Printf("Creating NIS2 assessment for org %s …", org.ID)
	assessment, err := client.CreateAssessment(ctx, org.ID, opensecstack.CreateAssessmentRequest{
		Title:            "Initial NIS2 Compliance Assessment",
		FrameworkVersion: "NIS2-2022/0383",
		Scope:            "All production systems and supporting infrastructure",
		Assessor:         "Security Team",
	})
	if err != nil {
		log.Fatalf("CreateAssessment: %v", err)
	}
	log.Printf("Assessment created: id=%s status=%s", assessment.ID, assessment.Status)

	// ------------------------------------------------------------------
	// 4. Stream the SARIF report to a local file.
	//
	// SARIF is the recommended format for integrating NIS2 gap findings
	// into code-review pipelines and GitHub Advanced Security.
	// ------------------------------------------------------------------
	reportFile := fmt.Sprintf("nis2-assessment-%s.sarif", assessment.ID)
	f, err := os.Create(reportFile)
	if err != nil {
		log.Fatalf("creating report file: %v", err)
	}
	defer f.Close()

	log.Printf("Streaming SARIF report to %s …", reportFile)
	reportCtx, cancel := context.WithTimeout(ctx, client.ReportTimeout)
	defer cancel()

	if err := client.GetReportStream(reportCtx, assessment.ID, "sarif", f); err != nil {
		log.Fatalf("GetReportStream: %v", err)
	}
	log.Printf("SARIF report written to %s", reportFile)

	// ------------------------------------------------------------------
	// Clean up: print summary and remind the caller that the org/assessment
	// can be removed with DeleteAssessment / DeleteOrganisation if needed.
	// ------------------------------------------------------------------
	fmt.Println("\n--- Summary ---")
	fmt.Printf("  Organisation : %s (%s)\n", org.Name, org.ID)
	fmt.Printf("  Assessment   : %s (%s)\n", assessment.Title, assessment.ID)
	fmt.Printf("  SARIF report : %s\n", reportFile)
	fmt.Println("\nTip: use DeleteAssessment / DeleteOrganisation to clean up test data.")
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
