// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Package exfil contains data exfiltration and covert-channel attack simulations.
// All attacks MUST target explicitly configured, isolated Docker environments.
package exfil

// Data exfiltration simulation.
//
// Makes authenticated bulk-enumeration requests against paginated API endpoints,
// recording how many records can be extracted before rate limiting or anomaly
// detection triggers. No actual data is stored or transmitted outside the lab.
//
// Safety guarantee: target URL is checked against the production blocklist.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DataExfilAttack simulates bulk data exfiltration via a REST API.
type DataExfilAttack struct {
	client *http.Client
}

// ExfilResult holds exfiltration simulation results.
type ExfilResult struct {
	Technique        string
	Success          bool
	Evidence         []string
	Duration         time.Duration
	RecordsExtracted int
	StopReason       string // "rate_limited", "anomaly_detected", "exhausted", "context_cancelled"
}

// NewDataExfilAttack returns a ready DataExfilAttack.
func NewDataExfilAttack() *DataExfilAttack {
	return &DataExfilAttack{client: &http.Client{Timeout: 10 * time.Second}}
}

// Run enumerates records from paginated endpoints until stopped.
//
// Recognised params keys:
//   - "jwt"           string — Bearer token (required)
//   - "endpoint"      string — base path, e.g. "/api/users" (default "/api/users")
//   - "page_param"    string — query param for page number (default "page")
//   - "limit_param"   string — query param for page size (default "limit")
//   - "page_size"     int    — records per page (default 100)
//   - "max_pages"     int    — stop after this many pages (default 50)
func (d *DataExfilAttack) Run(ctx context.Context, targetURL string, params map[string]any) (*ExfilResult, error) {
	if err := checkTarget(targetURL); err != nil {
		return nil, err
	}

	jwt, _ := params["jwt"].(string)
	if jwt == "" {
		return nil, errors.New("data_exfil: params[\"jwt\"] is required")
	}

	endpoint, _ := params["endpoint"].(string)
	if endpoint == "" {
		endpoint = "/api/users"
	}
	pageParam, _ := params["page_param"].(string)
	if pageParam == "" {
		pageParam = "page"
	}
	limitParam, _ := params["limit_param"].(string)
	if limitParam == "" {
		limitParam = "limit"
	}
	pageSize := intParam(params, "page_size", 100, 1000)
	maxPages := intParam(params, "max_pages", 50, 500)

	start := time.Now()
	result := &ExfilResult{Technique: "DataExfil"}
	base := strings.TrimRight(targetURL, "/")

	for page := 1; page <= maxPages; page++ {
		select {
		case <-ctx.Done():
			result.StopReason = "context_cancelled"
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		url := fmt.Sprintf("%s%s?%s=%d&%s=%d", base, endpoint, pageParam, page, limitParam, pageSize)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			break
		}
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("Accept", "application/json")

		resp, err := d.client.Do(req)
		if err != nil {
			result.Evidence = append(result.Evidence, fmt.Sprintf("DataExfil: page %d request failed: %v", page, err))
			break
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1 MB cap
		resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			result.StopReason = "rate_limited"
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("DataExfil: rate-limited on page %d after %d records", page, result.RecordsExtracted))
			result.Duration = time.Since(start)
			result.Success = result.RecordsExtracted > 0
			return result, nil

		case http.StatusForbidden, http.StatusUnauthorized:
			result.StopReason = "anomaly_detected"
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("DataExfil: access revoked (HTTP %d) on page %d after %d records — possible anomaly detection",
					resp.StatusCode, page, result.RecordsExtracted))
			result.Duration = time.Since(start)
			result.Success = result.RecordsExtracted > 0
			return result, nil

		case http.StatusOK:
			count := countRecords(body)
			result.RecordsExtracted += count
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("DataExfil: page %d — extracted %d records (total=%d)", page, count, result.RecordsExtracted))

			if count == 0 {
				// Empty page means we have exhausted the dataset.
				result.StopReason = "exhausted"
				result.Duration = time.Since(start)
				result.Success = result.RecordsExtracted > 0
				return result, nil
			}
		default:
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("DataExfil: unexpected HTTP %d on page %d", resp.StatusCode, page))
		}
	}

	result.StopReason = "exhausted"
	result.Duration = time.Since(start)
	result.Success = result.RecordsExtracted > 0
	return result, nil
}

// countRecords attempts to count items in a JSON array or an object with a
// "data", "items", "results", or "records" array field.
func countRecords(body []byte) int {
	var arr []any
	if err := json.Unmarshal(body, &arr); err == nil {
		return len(arr)
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return 0
	}
	for _, key := range []string{"data", "items", "results", "records", "users", "entries"} {
		if v, ok := obj[key]; ok {
			if a, ok := v.([]any); ok {
				return len(a)
			}
		}
	}
	return 0
}

// checkTarget rejects production-like URLs.
func checkTarget(targetURL string) error {
	lower := strings.ToLower(targetURL)
	for _, pattern := range []string{".prod", "-prod", "_prod", "production", ".live", "-live"} {
		if strings.Contains(lower, pattern) {
			return fmt.Errorf("safety: target URL matches production blocklist pattern (%s)", pattern)
		}
	}
	return nil
}

// intParam extracts an int from params with a default and cap.
func intParam(params map[string]any, key string, def, max int) int {
	v, ok := params[key]
	if !ok {
		return def
	}
	var n int
	switch vv := v.(type) {
	case int:
		n = vv
	case float64:
		n = int(vv)
	default:
		return def
	}
	if n > max {
		return max
	}
	if n < 1 {
		return def
	}
	return n
}
