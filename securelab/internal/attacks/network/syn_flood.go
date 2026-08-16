// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package network

// SYN Flood simulation.
//
// Uses net.Dial with TCP to open and immediately abandon connections, which
// exercises the server's SYN backlog without requiring raw socket privileges.
// This is a safe, portable simulation that does not forge IP headers.
//
// Safety guarantee: target must be a loopback or RFC 1918 address.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	synFloodDefaultPPS = 1000
	synFloodMaxPPS     = 10000
)

// SYNFlood simulates a TCP SYN flood against an isolated lab target.
type SYNFlood struct{}

// NewSYNFlood returns a ready SYNFlood.
func NewSYNFlood() *SYNFlood { return &SYNFlood{} }

// Run executes the SYN flood simulation.
//
// Recognised params keys:
//   - "pps"       int           — packets (connections) per second (default 1000, max 10000)
//   - "duration"  string        — how long to run, e.g. "5s" (default "5s", max "30s")
func (s *SYNFlood) Run(ctx context.Context, targetIP, targetPort string, params map[string]any) (*AttackResult, error) {
	if err := checkNetworkTarget(ctx, targetIP); err != nil {
		return nil, err
	}

	pps := intParam(params, "pps", synFloodDefaultPPS, synFloodMaxPPS)
	dur := durationParam(params, "duration", 5*time.Second, 30*time.Second)

	start := time.Now()
	result := &AttackResult{Technique: "SYNFlood"}

	addr := net.JoinHostPort(targetIP, targetPort)
	deadline := time.Now().Add(dur)

	interval := time.Duration(float64(time.Second) / float64(pps))

	var (
		sent   int64
		errors int64
	)

	var wg sync.WaitGroup
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			result.Duration = time.Since(start)
			addSYNStats(result, &sent, &errors)
			return result, ctx.Err()
		case t := <-ticker.C:
			if t.After(deadline) {
				wg.Wait()
				result.Duration = time.Since(start)
				addSYNStats(result, &sent, &errors)
				return result, nil
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", addr)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					return
				}
				// Immediately close — we are exercising the SYN backlog.
				conn.Close()
				atomic.AddInt64(&sent, 1)
			}()
		}
	}
}

func addSYNStats(r *AttackResult, sent, errs *int64) {
	s := atomic.LoadInt64(sent)
	e := atomic.LoadInt64(errs)
	r.Evidence = append(r.Evidence,
		fmt.Sprintf("SYNFlood: sent %d TCP SYN connections, %d errors over %.1fs",
			s, e, r.Duration.Seconds()))
	if s > 0 {
		r.Success = true
	}
}

// durationParam extracts a duration from params, capping at max.
func durationParam(params map[string]any, key string, def, max time.Duration) time.Duration {
	v, ok := params[key]
	if !ok {
		return def
	}
	var d time.Duration
	switch vv := v.(type) {
	case string:
		var err error
		d, err = time.ParseDuration(vv)
		if err != nil {
			return def
		}
	case time.Duration:
		d = vv
	default:
		return def
	}
	if d > max {
		return max
	}
	if d <= 0 {
		return def
	}
	return d
}
