//go:build integration

package integration_test

import (
	"context"
	"os"
	"testing"

	"github.com/opensecstack/sdk/go/opensecstack"
)

func apiGuardURL() string {
	if u := os.Getenv("INTEGRATION_APIGUARD_URL"); u != "" {
		return u
	}
	return "http://localhost:3000"
}

func nis2URL() string {
	if u := os.Getenv("INTEGRATION_NIS2_URL"); u != "" {
		return u
	}
	return "http://localhost:3000"
}

func TestGoAPIGuardIntegration(t *testing.T) {
	client := opensecstack.NewAPIGuardClient(apiGuardURL(), "test-api-key")
	ctx := context.Background()

	t.Run("list_scans", func(t *testing.T) {
		scans, err := client.ListScans(ctx, nil)
		if err != nil {
			t.Fatalf("ListScans: %v", err)
		}
		if len(scans) == 0 {
			t.Error("expected at least one scan")
		}
	})

	t.Run("create_scan", func(t *testing.T) {
		scan, err := client.CreateScan(ctx, "https://api.example.com/openapi.json")
		if err != nil {
			t.Fatalf("CreateScan: %v", err)
		}
		if scan.ID.String() == "" {
			t.Error("expected scan ID")
		}
	})

	t.Run("get_scan", func(t *testing.T) {
		scan, err := client.GetScan(ctx, "11111111-1111-1111-1111-111111111111")
		if err != nil {
			t.Fatalf("GetScan: %v", err)
		}
		if scan.Status == "" {
			t.Error("expected scan status")
		}
	})

	t.Run("get_findings", func(t *testing.T) {
		findings, err := client.GetFindings(ctx, "11111111-1111-1111-1111-111111111111", nil)
		if err != nil {
			t.Fatalf("GetFindings: %v", err)
		}
		if len(findings) == 0 {
			t.Error("expected at least one finding")
		}
	})
}

func citadelURL() string {
	if u := os.Getenv("INTEGRATION_CITADEL_URL"); u != "" {
		return u
	}
	return "http://localhost:3001"
}

func TestGoCitadelIntegration(t *testing.T) {
	client := opensecstack.NewCITADELClient(citadelURL(), "test-shared-secret")
	ctx := context.Background()

	var sentEventID string

	t.Run("send_event", func(t *testing.T) {
		event := opensecstack.SecurityEvent{
			ID:           "integ-go-001",
			EventType:    "apiguard.scan.completed",
			Source:       "apiguard",
			ActorID:      "test-api-key",
			ActorType:    "api_key",
			ResourceType: "scan",
			ResourceID:   "scan-integ-001",
			Severity:     "info",
			Payload:      map[string]interface{}{"score": 95},
			ChainHash:    "integ-genesis-go",
		}
		if err := client.SendEvent(ctx, event); err != nil {
			t.Fatalf("SendEvent: %v", err)
		}
		sentEventID = event.ID
	})

	t.Run("get_events", func(t *testing.T) {
		events, err := client.GetEvents(ctx, nil)
		if err != nil {
			t.Fatalf("GetEvents: %v", err)
		}
		if len(events) == 0 {
			t.Error("expected at least one event in the audit chain")
		}
	})

	t.Run("get_event", func(t *testing.T) {
		if sentEventID == "" {
			t.Skip("send_event sub-test did not produce an event ID")
		}
		event, err := client.GetEvent(ctx, sentEventID)
		if err != nil {
			t.Fatalf("GetEvent(%q): %v", sentEventID, err)
		}
		if event.ID != sentEventID {
			t.Errorf("GetEvent returned ID %q, want %q", event.ID, sentEventID)
		}
	})

	t.Run("verify_chain", func(t *testing.T) {
		events, err := client.GetEvents(ctx, nil)
		if err != nil {
			t.Fatalf("GetEvents for chain verification: %v", err)
		}
		if err := client.VerifyChain(events); err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
	})
}

func TestGoNIS2CompassIntegration(t *testing.T) {
	client := opensecstack.NewNIS2CompassClient(nis2URL(), "test-api-key")
	ctx := context.Background()

	t.Run("create_organisation", func(t *testing.T) {
		org, err := client.CreateOrganisation(ctx, opensecstack.CreateOrganisationRequest{
			Name: "Integration Test Org",
		})
		if err != nil {
			t.Fatalf("CreateOrganisation: %v", err)
		}
		if org.ID.String() == "" {
			t.Error("expected org ID")
		}
	})

	t.Run("create_assessment", func(t *testing.T) {
		assessment, err := client.CreateAssessment(ctx, "44444444-4444-4444-4444-444444444444", opensecstack.CreateAssessmentRequest{
			Title: "Integration Test Assessment",
		})
		if err != nil {
			t.Fatalf("CreateAssessment: %v", err)
		}
		if assessment.ID.String() == "" {
			t.Error("expected assessment ID")
		}
	})
}
