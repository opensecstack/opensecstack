// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package network

import (
	"context"
	"net"
	"testing"
)

func localUDPListener(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start UDP listener: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			_, _, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()

	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	return port
}

func TestUDPFlood_Run_BlocksPublicTarget(t *testing.T) {
	u := NewUDPFlood()
	_, err := u.Run(context.Background(), "1.1.1.1", "53", nil)
	if err == nil {
		t.Fatal("expected error for public IP target")
	}
}

func TestUDPFlood_Run_SendsDatagramsToLoopback(t *testing.T) {
	port := localUDPListener(t)
	u := NewUDPFlood()

	result, err := u.Run(context.Background(), "127.0.0.1", port, map[string]any{
		"duration": "300ms",
		"pps":      50,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected Success=true after sending datagrams")
	}
	if result.Technique != "UDPFlood" {
		t.Errorf("Technique = %q, want UDPFlood", result.Technique)
	}
}
