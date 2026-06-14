// citadel_events demonstrates the full CITADEL client lifecycle using the
// opensecstack Go SDK:
//
//  1. Build a CITADELClient with HMAC signing and retry options.
//  2. Send a test SecurityEvent (non-blocking — queued to background worker).
//  3. Query recent events with optional source and date filters.
//  4. Verify the SHA-256 hash chain across the returned events.
//  5. Fetch a single event by ID.
//  6. Drain the client on graceful shutdown.
//
// Prerequisites:
//
//	go run ./sdk/examples/go/citadel_events
//
// Required environment variables:
//
//	CITADEL_URL           Base URL of your CITADEL instance, e.g. https://citadel.internal
//	CITADEL_SHARED_SECRET HMAC-SHA256 shared signing secret
//
// Optional environment variables:
//
//	CITADEL_SOURCE        Source filter for GetEvents (default: "apiguard")
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	opensecstack "github.com/opensecstack/sdk/opensecstack"
)

func main() {
	ctx := context.Background()

	// ------------------------------------------------------------------
	// 1. Build the client.
	// ------------------------------------------------------------------
	baseURL := requireEnv("CITADEL_URL")
	sharedSecret := requireEnv("CITADEL_SHARED_SECRET")

	client := opensecstack.NewCITADELClient(opensecstack.CITADELClientOptions{
		BaseURL:       baseURL,
		SharedSecret:  sharedSecret,
		MaxRetries:    3,
		RetryWaitBase: 500 * time.Millisecond,
	})

	fmt.Printf("CITADEL client created — base URL: %s\n", baseURL)

	// ------------------------------------------------------------------
	// 2. Send a test event (non-blocking).
	// ------------------------------------------------------------------
	payload, _ := json.Marshal(map[string]interface{}{
		"scan_id":          "scan_abc123",
		"spec_hash":        "sha256:deadbeef",
		"findings_summary": map[string]int{"critical": 0, "high": 1, "medium": 3},
	})

	event := opensecstack.SecurityEvent{
		ID:           "evt_" + fmt.Sprintf("%d", time.Now().UnixNano()),
		EventType:    "apiguard.scan.completed",
		Source:       "apiguard",
		ActorID:      "ak_example_key",
		ActorType:    "api_key",
		ResourceType: "scan",
		ResourceID:   "scan_abc123",
		Severity:     "info",
		Payload:      json.RawMessage(payload),
		ChainHash:    "0000000000000000000000000000000000000000000000000000000000000000",
		Timestamp:    time.Now().UTC(),
	}

	if err := client.SendEvent(ctx, event); err != nil {
		log.Printf("SendEvent: %v", err)
	} else {
		fmt.Printf("Event %s queued for delivery (non-blocking)\n", event.ID)
	}

	// Brief pause so the background worker can deliver the event before we
	// proceed with queries.  In production code you would call Drain on shutdown
	// instead of sleeping here.
	time.Sleep(200 * time.Millisecond)

	// ------------------------------------------------------------------
	// 3. Query recent events.
	// ------------------------------------------------------------------
	source := os.Getenv("CITADEL_SOURCE")
	if source == "" {
		source = "apiguard"
	}
	since := time.Now().UTC().Add(-24 * time.Hour)

	fmt.Printf("\nQuerying events: source=%s, since=%s\n", source, since.Format(time.RFC3339))

	events, err := client.GetEvents(ctx, opensecstack.GetEventsOptions{
		Source: source,
		Since:  &since,
		Limit:  20,
		Page:   1,
	})
	if err != nil {
		log.Fatalf("GetEvents: %v", err)
	}
	fmt.Printf("Retrieved %d event(s)\n", len(events))
	for _, e := range events {
		fmt.Printf("  [%s] %s | %s | %s\n",
			e.Timestamp.Format("2006-01-02T15:04:05Z"),
			e.ID,
			e.EventType,
			e.Severity,
		)
	}

	// ------------------------------------------------------------------
	// 4. Verify the hash chain across the returned events.
	// ------------------------------------------------------------------
	if len(events) >= 2 {
		fmt.Printf("\nVerifying hash chain across %d events…\n", len(events))
		if err := client.VerifyChain(ctx, events); err != nil {
			fmt.Printf("  Chain verification FAILED: %v\n", err)
		} else {
			fmt.Println("  Chain intact — all links verified.")
		}
	} else {
		fmt.Println("\nSkipping chain verification (fewer than 2 events returned)")
	}

	// ------------------------------------------------------------------
	// 5. Fetch a single event by ID (using the last event retrieved).
	// ------------------------------------------------------------------
	if len(events) > 0 {
		targetID := events[len(events)-1].ID
		fmt.Printf("\nFetching single event by ID: %s\n", targetID)
		single, err := client.GetEvent(ctx, targetID)
		if err != nil {
			log.Printf("GetEvent: %v", err)
		} else {
			fmt.Printf("  Fetched: %s | %s | chain_hash: %.16s…\n",
				single.ID, single.EventType, single.ChainHash)
		}
	}

	// ------------------------------------------------------------------
	// 6. Graceful shutdown — drain the client.
	// ------------------------------------------------------------------
	fmt.Println("\nDraining client (waiting for in-flight deliveries)…")
	drainCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Drain(drainCtx); err != nil {
		log.Printf("Drain: %v", err)
	} else {
		fmt.Println("Drain complete.")
	}
}

// requireEnv returns the value of the named environment variable or exits.
func requireEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		fmt.Fprintf(os.Stderr, "error: required environment variable %s is not set\n", name)
		os.Exit(1)
	}
	return v
}
