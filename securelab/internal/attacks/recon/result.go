// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Package recon contains reconnaissance attack simulations (port scanning,
// endpoint enumeration, version detection).
// All attacks MUST target RFC 1918 or loopback addresses only.
package recon

import (
	"errors"
	"net"
	"time"
)

// AttackResult holds the outcome of a recon simulation.
type AttackResult struct {
	Technique string
	Success   bool
	Evidence  []string
	Duration  time.Duration
}

// checkTarget enforces that the target host resolves to a private/loopback IP.
func checkTarget(host string) error {
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return errors.New("safety: cannot resolve target host")
		}
		ip = net.ParseIP(addrs[0])
		if ip == nil {
			return errors.New("safety: unable to parse resolved IP")
		}
	}
	if ip.IsLoopback() || isRFC1918(ip) {
		return nil
	}
	return errors.New("safety: target is not loopback or RFC 1918; recon attacks restricted to isolated lab environments")
}

func isRFC1918(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	for _, r := range []struct {
		net  net.IP
		mask net.IPMask
	}{
		{net.IP{10, 0, 0, 0}, net.IPMask{255, 0, 0, 0}},
		{net.IP{172, 16, 0, 0}, net.IPMask{255, 240, 0, 0}},
		{net.IP{192, 168, 0, 0}, net.IPMask{255, 255, 0, 0}},
	} {
		if ip.Mask(r.mask).Equal(r.net) {
			return true
		}
	}
	return false
}
