// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package network

// UDP Flood simulation.
//
// Sends UDP datagrams at the configured rate for a configured duration.
// Uses net.Dial("udp", ...) — no raw socket privileges required.
//
// Safety guarantee: target must be a loopback or RFC 1918 address.

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

const (
	udpFloodDefaultPPS = 1000
	udpFloodMaxPPS     = 10000
)

// udpPayload is the fixed datagram payload sent in each packet.
var udpPayload = []byte("SecureLab-UDP-Flood-Simulation-Packet")

// UDPFlood simulates a UDP flood against an isolated lab target.
type UDPFlood struct{}

// NewUDPFlood returns a ready UDPFlood.
func NewUDPFlood() *UDPFlood { return &UDPFlood{} }

// Run executes the UDP flood simulation.
//
// Recognised params keys:
//   - "pps"       int    — datagrams per second (default 1000, max 10000)
//   - "duration"  string — how long to run, e.g. "5s" (default "5s", max "30s")
func (u *UDPFlood) Run(ctx context.Context, targetIP, targetPort string, params map[string]any) (*AttackResult, error) {
	if err := checkNetworkTarget(targetIP); err != nil {
		return nil, err
	}

	pps := intParam(params, "pps", udpFloodDefaultPPS, udpFloodMaxPPS)
	dur := durationParam(params, "duration", 5*time.Second, 30*time.Second)

	start := time.Now()
	result := &AttackResult{Technique: "UDPFlood"}

	addr := net.JoinHostPort(targetIP, targetPort)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("udp_flood: dial %s: %w", addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(dur)
	interval := time.Duration(float64(time.Second) / float64(pps))

	var (
		sent   int64
		errors int64
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			addUDPStats(result, &sent, &errors)
			return result, ctx.Err()
		case t := <-ticker.C:
			if t.After(deadline) {
				result.Duration = time.Since(start)
				addUDPStats(result, &sent, &errors)
				return result, nil
			}
			if _, err := conn.Write(udpPayload); err != nil {
				atomic.AddInt64(&errors, 1)
			} else {
				atomic.AddInt64(&sent, 1)
			}
		}
	}
}

func addUDPStats(r *AttackResult, sent, errs *int64) {
	s := atomic.LoadInt64(sent)
	e := atomic.LoadInt64(errs)
	r.Evidence = append(r.Evidence,
		fmt.Sprintf("UDPFlood: sent %d datagrams, %d errors over %.1fs",
			s, e, r.Duration.Seconds()))
	if s > 0 {
		r.Success = true
	}
}
