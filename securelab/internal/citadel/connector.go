// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Package citadel provides a CITADEL event emitter for SecureLab.
// Events are signed with HMAC-SHA256 and posted to the CITADEL ingest endpoint
// using the same wire format as the OpenCSIRT CITADEL emitter.
package citadel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Connector signs and emits SecureLab events to a CITADEL endpoint.
type Connector struct {
	citadelURL string
	secret     []byte
	client     *http.Client
}

// NewConnector creates a Connector that posts to citadelURL, signing payloads
// with the provided HMAC secret.
func NewConnector(citadelURL, hmacSecret string) *Connector {
	return &Connector{
		citadelURL: citadelURL,
		secret:     []byte(hmacSecret),
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// runCompletedEvent is the canonical wire format for securelab.run_completed.
// It is carried as the `payload` field of a CITADEL WORM emit request.
type runCompletedEvent struct {
	EventType     string    `json:"event_type"`
	EventID       string    `json:"event_id"`
	Source        string    `json:"source"`
	SpecVersion   string    `json:"spec_version"`
	Timestamp     time.Time `json:"timestamp"`
	RunID         string    `json:"run_id"`
	ScenarioName  string    `json:"scenario_name"`
	Status        string    `json:"status"`
	DetectionRate float64   `json:"detection_rate"`
}

// emitRequest is the body for POST /api/v1/worm/emit on CITADEL, matching
// citadel/internal/api/handlers/worm.go's emitRequest struct.
type emitRequest struct {
	Source    string          `json:"source"`
	EventType string          `json:"event_type"`
	ProjectID string          `json:"project_id"`
	Payload   json.RawMessage `json:"payload"`
}

// EmitRunCompleted signs and POSTs a securelab.run_completed CITADEL event.
//
// The request includes an X-CITADEL-Signature header containing
// "sha256=<hex(HMAC-SHA256(secret, body))>" for server-side verification,
// matching the OpenCSIRT CITADEL wire format.
func (c *Connector) EmitRunCompleted(ctx context.Context, runID, scenarioName, status string, detectionRate float64) error {
	event := runCompletedEvent{
		EventType:     "securelab.run_completed",
		EventID:       fmt.Sprintf("%s-%d", runID, time.Now().UnixNano()),
		Source:        "securelab",
		SpecVersion:   "1.0",
		Timestamp:     time.Now().UTC(),
		RunID:         runID,
		ScenarioName:  scenarioName,
		Status:        status,
		DetectionRate: detectionRate,
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("citadel: marshal event: %w", err)
	}

	emit := emitRequest{
		Source:    "securelab",
		EventType: event.EventType,
		Payload:   payload,
	}

	body, err := json.Marshal(emit)
	if err != nil {
		return fmt.Errorf("citadel: marshal emit request: %w", err)
	}

	sig := c.sign(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.citadelURL+"/api/v1/worm/emit", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("citadel: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CITADEL-Signature", "sha256="+sig)
	req.Header.Set("X-CITADEL-Source", "securelab")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("citadel: post event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("citadel: server returned HTTP %d for event %s", resp.StatusCode, event.EventID)
	}
	return nil
}

// sign returns the hex-encoded HMAC-SHA256 of body under c.secret.
func (c *Connector) sign(body []byte) string {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
