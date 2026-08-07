// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package network

// HTTP Flood simulation.
//
// Launches concurrent goroutines that hammer a target URL with GET requests,
// measuring response times to surface degradation under load.
//
// Safety guarantee: target must be a loopback or RFC 1918 address.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	httpFloodDefaultConcurrency = 10
	httpFloodMaxConcurrency     = 100
)

// HTTPFlood simulates an HTTP flood (Layer 7) against an isolated lab target.
type HTTPFlood struct{}

// NewHTTPFlood returns a ready HTTPFlood.
func NewHTTPFlood() *HTTPFlood { return &HTTPFlood{} }

// Run executes the HTTP flood simulation.
//
// Recognised params keys:
//   - "concurrency" int    — parallel goroutines (default 10, max 100)
//   - "requests"    int    — total requests to send (default 500)
//   - "duration"    string — alternative to requests: run for this long, e.g. "10s" (max "60s")
//   - "path"        string — URL path to flood (default "/")
func (h *HTTPFlood) Run(ctx context.Context, targetIP, targetPort string, params map[string]any) (*AttackResult, error) {
	if err := checkNetworkTarget(targetIP); err != nil {
		return nil, err
	}

	concurrency := intParam(params, "concurrency", httpFloodDefaultConcurrency, httpFloodMaxConcurrency)
	totalRequests := intParam(params, "requests", 500, 1_000_000)
	dur := durationParam(params, "duration", 0, 60*time.Second)

	path, _ := params["path"].(string)
	if path == "" {
		path = "/"
	}

	targetURL := fmt.Sprintf("http://%s:%s%s", targetIP, targetPort, path)

	start := time.Now()
	result := &AttackResult{Technique: "HTTPFlood"}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: concurrency,
			DisableKeepAlives:   false,
		},
	}

	var (
		sent      int64
		successes int64
		failures  int64
		mu        sync.Mutex
		latencies []time.Duration
	)

	work := make(chan struct{}, totalRequests)
	if dur > 0 {
		// Duration mode: fill channel continuously until deadline.
		go func() {
			deadline := time.Now().Add(dur)
			for time.Now().Before(deadline) {
				select {
				case work <- struct{}{}:
				case <-ctx.Done():
					close(work)
					return
				}
			}
			close(work)
		}()
	} else {
		// Count mode.
		for i := 0; i < totalRequests; i++ {
			work <- struct{}{}
		}
		close(work)
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				reqStart := time.Now()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
				if err != nil {
					atomic.AddInt64(&failures, 1)
					continue
				}

				resp, err := client.Do(req)
				lat := time.Since(reqStart)
				atomic.AddInt64(&sent, 1)

				if err != nil {
					atomic.AddInt64(&failures, 1)
					continue
				}
				resp.Body.Close()

				if resp.StatusCode < 500 {
					atomic.AddInt64(&successes, 1)
				} else {
					atomic.AddInt64(&failures, 1)
				}

				mu.Lock()
				latencies = append(latencies, lat)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	result.Duration = time.Since(start)

	s := atomic.LoadInt64(&sent)
	ok := atomic.LoadInt64(&successes)
	fail := atomic.LoadInt64(&failures)

	if s > 0 {
		result.Success = true
	}

	p50, p95, p99 := percentiles(latencies)
	result.Evidence = append(result.Evidence,
		fmt.Sprintf("HTTPFlood: %d requests in %.1fs — %d ok, %d errors; p50=%s p95=%s p99=%s",
			s, result.Duration.Seconds(), ok, fail, p50.Round(time.Millisecond), p95.Round(time.Millisecond), p99.Round(time.Millisecond)))

	return result, nil
}

// percentiles returns p50, p95, p99 from a slice of durations.
func percentiles(d []time.Duration) (p50, p95, p99 time.Duration) {
	if len(d) == 0 {
		return 0, 0, 0
	}
	sorted := make([]time.Duration, len(d))
	copy(sorted, d)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := func(pct float64) time.Duration {
		i := int(float64(len(sorted)-1) * pct)
		return sorted[i]
	}
	return idx(0.50), idx(0.95), idx(0.99)
}
