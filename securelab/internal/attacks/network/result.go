// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Package network contains network-layer attack simulations (flood, slowloris).
// All attacks MUST target RFC 1918 or loopback addresses only — never public IPs.
package network

import (
	"context"
	"errors"
	"net"
	"time"
)

// AttackResult holds the outcome of a network attack simulation.
type AttackResult struct {
	Technique string
	Success   bool
	Evidence  []string
	Duration  time.Duration
}

// checkNetworkTarget enforces that the target is a loopback or RFC 1918 address.
// This prevents accidental flood attacks against production or third-party hosts.
func checkNetworkTarget(ctx context.Context, host string) error {
	ip := net.ParseIP(host)
	if ip == nil {
		// Try resolving a hostname — must resolve to a private address.
		addrs, err := new(net.Resolver).LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return errors.New("safety: cannot resolve target host")
		}
		ip = net.ParseIP(addrs[0])
		if ip == nil {
			return errors.New("safety: unable to parse resolved IP for target host")
		}
	}

	if ip.IsLoopback() || isRFC1918(ip) {
		return nil
	}
	return errors.New("safety: target IP is not a loopback or RFC 1918 address; network attacks are restricted to isolated lab environments")
}

// isRFC1918 returns true for 10.x.x.x, 172.16-31.x.x, and 192.168.x.x.
func isRFC1918(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	private := []struct {
		network net.IP
		mask    net.IPMask
	}{
		{net.IP{10, 0, 0, 0}, net.IPMask{255, 0, 0, 0}},
		{net.IP{172, 16, 0, 0}, net.IPMask{255, 240, 0, 0}},
		{net.IP{192, 168, 0, 0}, net.IPMask{255, 255, 0, 0}},
	}
	for _, r := range private {
		if ip.Mask(r.mask).Equal(r.network) {
			return true
		}
	}
	return false
}

// intParam extracts an int from params with a default and an optional cap.
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
	if n <= 0 {
		return def
	}
	return n
}
