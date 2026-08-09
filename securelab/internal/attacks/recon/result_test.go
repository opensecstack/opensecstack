// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package recon

import (
	"net"
	"testing"
)

func TestCheckTarget_AllowsLoopbackAndRFC1918(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.1.2.3", "172.20.0.5", "192.168.50.1"} {
		if err := checkTarget(host); err != nil {
			t.Errorf("checkTarget(%q) = %v, want nil", host, err)
		}
	}
}

func TestCheckTarget_BlocksPublicIP(t *testing.T) {
	if err := checkTarget("1.1.1.1"); err == nil {
		t.Error("expected public IP to be blocked")
	}
}

func TestCheckTarget_BlocksUnresolvableHost(t *testing.T) {
	if err := checkTarget("definitely-not-a-real-host.invalid"); err == nil {
		t.Error("expected unresolvable host to error")
	}
}

func TestIsRFC1918_ReconPackage(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"172.16.5.5", true},
		{"192.168.1.1", true},
		{"11.0.0.1", false},
		{"172.32.0.1", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := isRFC1918(ip); got != tt.want {
			t.Errorf("isRFC1918(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
