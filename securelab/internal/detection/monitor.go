// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Package detection provides alert monitoring, verification, timing analysis,
// and gap reporting against SecureLab's integrated detection platforms
// (OpenScrub, APIGuard, ThreatFlow).
package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AlertEvent represents a single alert emitted by a detection platform.
type AlertEvent struct {
	Platform  string
	AlertID   string
	Technique string
	Severity  string
	Timestamp time.Time
}

// Monitor polls configured detection platform APIs for alerts matching a run.
type Monitor struct {
	openscrubURL  string
	apiguardURL   string
	threatflowURL string
	client        *http.Client
}

// NewMonitor returns a Monitor. Any of the URL fields may be empty; the
// corresponding platform will simply be skipped during polling.
func NewMonitor(openscrubURL, apiguardURL, threatflowURL string) *Monitor {
	return &Monitor{
		openscrubURL:  openscrubURL,
		apiguardURL:   apiguardURL,
		threatflowURL: threatflowURL,
		client:        &http.Client{Timeout: 5 * time.Second},
	}
}

// WatchAlerts polls all configured platforms every 2 seconds and forwards any
// AlertEvents whose Technique matches one of expectedTechniques OR whose
// metadata references runID. The channel is closed when ctx is cancelled.
func (m *Monitor) WatchAlerts(ctx context.Context, runID string, expectedTechniques []string) <-chan AlertEvent {
	ch := make(chan AlertEvent, 64)

	techniqueSet := make(map[string]struct{}, len(expectedTechniques))
	for _, t := range expectedTechniques {
		techniqueSet[strings.ToLower(t)] = struct{}{}
	}

	go func() {
		defer close(ch)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		type platform struct {
			name string
			url  string
		}
		platforms := []platform{
			{"openscrub", m.openscrubURL},
			{"apiguard", m.apiguardURL},
			{"threatflow", m.threatflowURL},
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, p := range platforms {
					if p.url == "" {
						continue
					}
					events, err := m.fetchAlerts(ctx, p.name, p.url, runID)
					if err != nil {
						continue
					}
					for _, ev := range events {
						_, techMatch := techniqueSet[strings.ToLower(ev.Technique)]
						// An empty techniqueSet means the caller passed no
						// technique filter at all (e.g. MonitorAdapter's
						// "accept any alert" mode) and must match every
						// event, not just ones with an empty Technique field.
						noFilter := len(techniqueSet) == 0
						if noFilter || techMatch || ev.Technique == "" {
							select {
							case ch <- ev:
							case <-ctx.Done():
								return
							}
						}
					}
				}
			}
		}
	}()

	return ch
}

// fetchAlerts queries a single platform's alert API endpoint.
// The expected response is a JSON array of alert objects.
func (m *Monitor) fetchAlerts(ctx context.Context, platform, baseURL, runID string) ([]AlertEvent, error) {
	url := fmt.Sprintf("%s/api/v1/alerts?run_id=%s", strings.TrimRight(baseURL, "/"), runID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("monitor: %s returned HTTP %d", platform, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	// Expect either a raw array or an envelope {"alerts": [...]}
	var raw []map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		var envelope struct {
			Alerts []map[string]any `json:"alerts"`
		}
		if err2 := json.Unmarshal(body, &envelope); err2 != nil {
			return nil, fmt.Errorf("monitor: %s: cannot parse response: %w", platform, err)
		}
		raw = envelope.Alerts
	}

	events := make([]AlertEvent, 0, len(raw))
	for _, item := range raw {
		ev := AlertEvent{Platform: platform}
		if v, ok := item["alert_id"].(string); ok {
			ev.AlertID = v
		}
		if v, ok := item["technique"].(string); ok {
			ev.Technique = v
		}
		if v, ok := item["severity"].(string); ok {
			ev.Severity = v
		}
		if v, ok := item["timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				ev.Timestamp = t
			}
		}
		if ev.Timestamp.IsZero() {
			ev.Timestamp = time.Now()
		}
		events = append(events, ev)
	}
	return events, nil
}
