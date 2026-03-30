// webhook_receiver is a minimal HTTP server that listens for signed webhook
// events from the opensecstack platforms (APIGuard, NIS2 Compass, CITADEL)
// and dispatches them to typed handlers.
//
// # Quick start
//
//	WEBHOOK_SECRET=my-secret go run ./sdk/examples/go/webhook_receiver
//
// The server listens on :8080 by default (override with the PORT env var).
// Send a test event with:
//
//	curl -X POST http://localhost:8080/webhooks \
//	  -H "Content-Type: application/json" \
//	  -H "X-APIGuard-Signature: sha256=$(echo -n '{"id":"evt_1",...}' | openssl dgst -sha256 -hmac my-secret | cut -d' ' -f2)" \
//	  -d '{"id":"evt_1","event_type":"apiguard.scan.completed","source":"apiguard","timestamp":"2026-03-30T00:00:00Z","payload":{"scan_id":"abc"}}'
//
// Required environment variables:
//
//	WEBHOOK_SECRET   Shared HMAC-SHA256 secret configured on the platform
//
// Optional environment variables:
//
//	PORT             TCP port to listen on (default: 8080)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/opensecstack/sdk/opensecstack"
)

func main() {
	secret := os.Getenv("WEBHOOK_SECRET")
	if secret == "" {
		log.Fatal("WEBHOOK_SECRET environment variable is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	router := opensecstack.NewWebhookRouter(secret)

	// --- APIGuard: scan completed -------------------------------------------
	router.On(opensecstack.EventAPIScanCompleted, func(ctx context.Context, e opensecstack.WebhookEvent) error {
		var payload struct {
			ScanID string `json:"scan_id"`
			Target string `json:"target"`
			Stats  struct {
				Total    int `json:"total"`
				Critical int `json:"critical"`
				High     int `json:"high"`
				Medium   int `json:"medium"`
				Low      int `json:"low"`
			} `json:"stats"`
		}
		if err := json.Unmarshal(e.Payload, &payload); err != nil {
			return fmt.Errorf("unmarshal scan.completed payload: %w", err)
		}
		log.Printf("[apiguard.scan.completed] evt=%s scan=%s target=%s findings(crit=%d high=%d med=%d low=%d total=%d)",
			e.ID, payload.ScanID, payload.Target,
			payload.Stats.Critical, payload.Stats.High,
			payload.Stats.Medium, payload.Stats.Low, payload.Stats.Total,
		)
		return nil
	})

	// --- NIS2 Compass: assessment completed ---------------------------------
	router.On(opensecstack.EventNIS2AssessmentComplete, func(ctx context.Context, e opensecstack.WebhookEvent) error {
		var payload struct {
			OrgID        string `json:"org_id"`
			AssessmentID string `json:"assessment_id"`
			Stats        struct {
				Compliant          int `json:"compliant"`
				PartiallyCompliant int `json:"partially_compliant"`
				NonCompliant       int `json:"non_compliant"`
				NotApplicable      int `json:"not_applicable"`
			} `json:"stats"`
		}
		if err := json.Unmarshal(e.Payload, &payload); err != nil {
			return fmt.Errorf("unmarshal assessment.completed payload: %w", err)
		}
		log.Printf("[nis2compass.assessment.completed] evt=%s org=%s assessment=%s compliant=%d partial=%d non_compliant=%d",
			e.ID, payload.OrgID, payload.AssessmentID,
			payload.Stats.Compliant, payload.Stats.PartiallyCompliant, payload.Stats.NonCompliant,
		)
		return nil
	})

	// --- CITADEL: hard stop -------------------------------------------------
	router.On(opensecstack.EventCITADELHardStop, func(ctx context.Context, e opensecstack.WebhookEvent) error {
		var payload struct {
			ExecutionID     string `json:"execution_id"`
			ActorUserID     string `json:"actor_user_id"`
			Trigger         string `json:"trigger"`
			IRFlowIncidentID string `json:"irflow_incident_id"`
		}
		if err := json.Unmarshal(e.Payload, &payload); err != nil {
			return fmt.Errorf("unmarshal citadel.hard_stop payload: %w", err)
		}
		log.Printf("[CITADEL HARD STOP] evt=%s execution=%s actor=%s trigger=%s incident=%s",
			e.ID, payload.ExecutionID, payload.ActorUserID,
			payload.Trigger, payload.IRFlowIncidentID,
		)
		return nil
	})

	// --- Catch-all: log any unhandled event type ----------------------------
	router.On("*", func(ctx context.Context, e opensecstack.WebhookEvent) error {
		log.Printf("[webhook] unhandled event type=%s id=%s source=%s", e.EventType, e.ID, e.Source)
		return nil
	})

	addr := ":" + port
	log.Printf("webhook_receiver listening on %s  (POST /webhooks)", addr)
	http.Handle("/webhooks", router)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
