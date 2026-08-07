// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package recon

// TCP connect port scanner.
//
// Performs a standard TCP connect scan across a configurable port range.
// Uses concurrent workers controlled by a semaphore for throughput.
//
// Safety guarantee: target must be loopback or RFC 1918.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// OpenPort holds the result for a single open port.
type OpenPort struct {
	Port    int
	Banner  string // optional service banner grabbed from the connection
}

// PortScanResult extends AttackResult with discovered open ports.
type PortScanResult struct {
	AttackResult
	OpenPorts []OpenPort
}

// PortScanner performs TCP connect scans.
type PortScanner struct{}

// NewPortScanner returns a ready PortScanner.
func NewPortScanner() *PortScanner { return &PortScanner{} }

// Run scans [startPort, endPort] on targetHost.
//
// Recognised params keys:
//   - "start_port"   int    — first port (default 1)
//   - "end_port"     int    — last port  (default 1024)
//   - "timeout_ms"   int    — per-port dial timeout in milliseconds (default 500)
//   - "concurrency"  int    — parallel probes (default 50, max 500)
func (p *PortScanner) Run(ctx context.Context, targetHost string, params map[string]any) (*PortScanResult, error) {
	if err := checkTarget(targetHost); err != nil {
		return nil, err
	}

	startPort := intParam(params, "start_port", 1, 65535)
	endPort := intParam(params, "end_port", 1024, 65535)
	timeoutMS := intParam(params, "timeout_ms", 500, 30000)
	concurrency := intParam(params, "concurrency", 50, 500)

	if startPort > endPort {
		startPort, endPort = endPort, startPort
	}

	timeout := time.Duration(timeoutMS) * time.Millisecond
	start := time.Now()
	result := &PortScanResult{
		AttackResult: AttackResult{Technique: "PortScan"},
	}

	type portResult struct {
		port   int
		open   bool
		banner string
	}

	ports := make(chan int, concurrency)
	results := make(chan portResult, endPort-startPort+1)
	var wg sync.WaitGroup

	// Workers.
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				select {
				case <-ctx.Done():
					return
				default:
				}

				addr := fmt.Sprintf("%s:%d", targetHost, port)
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err != nil {
					results <- portResult{port: port, open: false}
					continue
				}

				// Attempt a banner grab.
				banner := ""
				conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				if n > 0 {
					banner = sanitiseBanner(buf[:n])
				}
				conn.Close()

				results <- portResult{port: port, open: true, banner: banner}
			}
		}()
	}

	// Feed ports.
	go func() {
		for port := startPort; port <= endPort; port++ {
			select {
			case <-ctx.Done():
				break
			case ports <- port:
			}
		}
		close(ports)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.open {
			result.OpenPorts = append(result.OpenPorts, OpenPort{Port: r.port, Banner: r.banner})
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("PortScan: port %d/tcp open on %s (banner=%q)", r.port, targetHost, r.banner))
		}
	}

	result.Duration = time.Since(start)
	if len(result.OpenPorts) > 0 {
		result.Success = true
	}
	return result, ctx.Err()
}

// sanitiseBanner strips non-printable characters from a banner.
func sanitiseBanner(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		}
	}
	s := string(out)
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

// intParam extracts an int from params, clamped to [1, max].
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
