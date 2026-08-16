// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package network

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCheckNetworkTarget_AllowsLoopback(t *testing.T) {
	if err := checkNetworkTarget(context.Background(), "127.0.0.1"); err != nil {
		t.Errorf("expected loopback to be allowed, got: %v", err)
	}
}

func TestCheckNetworkTarget_AllowsRFC1918(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1"} {
		if err := checkNetworkTarget(context.Background(), ip); err != nil {
			t.Errorf("checkNetworkTarget(%q) = %v, want nil", ip, err)
		}
	}
}

func TestCheckNetworkTarget_BlocksPublicIP(t *testing.T) {
	if err := checkNetworkTarget(context.Background(), "8.8.8.8"); err == nil {
		t.Error("expected public IP 8.8.8.8 to be blocked")
	}
}

func TestCheckNetworkTarget_BlocksUnresolvableHost(t *testing.T) {
	if err := checkNetworkTarget(context.Background(), "this-host-does-not-exist.invalid"); err == nil {
		t.Error("expected unresolvable host to error")
	}
}

func TestIsRFC1918_BoundaryAddresses(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"172.15.255.255", false}, // just below 172.16/12
		{"172.16.0.0", true},
		{"172.31.255.255", true},
		{"172.32.0.0", false}, // just above 172.31/12
		{"192.167.255.255", false},
		{"192.168.0.0", true},
		{"9.255.255.255", false},
		{"10.0.0.0", true},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %q", tt.ip)
		}
		if got := isRFC1918(ip); got != tt.want {
			t.Errorf("isRFC1918(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// intParam / durationParam
// ---------------------------------------------------------------------------

func TestIntParam_NetworkPackage(t *testing.T) {
	if got := intParam(map[string]any{}, "k", 10, 100); got != 10 {
		t.Errorf("default: got %d, want 10", got)
	}
	if got := intParam(map[string]any{"k": 50}, "k", 10, 100); got != 50 {
		t.Errorf("int value: got %d, want 50", got)
	}
	if got := intParam(map[string]any{"k": 500}, "k", 10, 100); got != 100 {
		t.Errorf("capped at max: got %d, want 100", got)
	}
	if got := intParam(map[string]any{"k": -5}, "k", 10, 100); got != 10 {
		t.Errorf("non-positive falls back to default: got %d, want 10", got)
	}
	if got := intParam(map[string]any{"k": float64(30)}, "k", 10, 100); got != 30 {
		t.Errorf("float64 value: got %d, want 30", got)
	}
}

func TestDurationParam(t *testing.T) {
	if got := durationParam(map[string]any{}, "k", 5*time.Second, 30*time.Second); got != 5*time.Second {
		t.Errorf("default: got %v, want 5s", got)
	}
	if got := durationParam(map[string]any{"k": "10s"}, "k", 5*time.Second, 30*time.Second); got != 10*time.Second {
		t.Errorf("parsed string: got %v, want 10s", got)
	}
	if got := durationParam(map[string]any{"k": "1h"}, "k", 5*time.Second, 30*time.Second); got != 30*time.Second {
		t.Errorf("capped at max: got %v, want 30s", got)
	}
	if got := durationParam(map[string]any{"k": "not-a-duration"}, "k", 5*time.Second, 30*time.Second); got != 5*time.Second {
		t.Errorf("invalid string falls back to default: got %v, want 5s", got)
	}
	if got := durationParam(map[string]any{"k": "-1s"}, "k", 5*time.Second, 30*time.Second); got != 5*time.Second {
		t.Errorf("non-positive falls back to default: got %v, want 5s", got)
	}
}
