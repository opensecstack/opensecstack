// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package dispatch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opensecstack/securelab/internal/scenarios"
)

// ---------------------------------------------------------------------------
// splitNetworkTarget / extractHostname (pure, unexported helpers)
// ---------------------------------------------------------------------------

func TestSplitNetworkTarget_WithPort(t *testing.T) {
	ip, port, err := splitNetworkTarget("http://192.168.1.5:9090/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "192.168.1.5" || port != "9090" {
		t.Errorf("ip=%q port=%q, want 192.168.1.5 9090", ip, port)
	}
}

func TestSplitNetworkTarget_NoPortDefaultsTo80(t *testing.T) {
	ip, port, err := splitNetworkTarget("http://192.168.1.5/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "192.168.1.5" || port != "80" {
		t.Errorf("ip=%q port=%q, want 192.168.1.5 80", ip, port)
	}
}

func TestSplitNetworkTarget_NoHost(t *testing.T) {
	_, _, err := splitNetworkTarget("/just/a/path")
	if err == nil {
		t.Fatal("expected error for URL with no host")
	}
}

func TestSplitNetworkTarget_InvalidURL(t *testing.T) {
	_, _, err := splitNetworkTarget("://bad-url")
	if err == nil {
		t.Fatal("expected error for unparseable URL")
	}
}

func TestExtractHostname_Basic(t *testing.T) {
	h, err := extractHostname("http://10.0.0.1:8080/x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != "10.0.0.1" {
		t.Errorf("hostname = %q, want 10.0.0.1 (no port)", h)
	}
}

func TestExtractHostname_NoHost(t *testing.T) {
	_, err := extractHostname("not-a-url-at-all-with-no-scheme-or-host")
	if err == nil {
		t.Fatal("expected error for URL with no host")
	}
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

func TestDispatch_UnknownKind(t *testing.T) {
	d := NewDispatcher()
	_, err := d.Dispatch(context.Background(), scenarios.StepSpec{Kind: "not_a_real_kind"}, "http://127.0.0.1:8080")
	if err == nil {
		t.Fatal("expected error for unknown step kind")
	}
	if !strings.Contains(err.Error(), "unknown step kind") {
		t.Errorf("error = %v, want message mentioning 'unknown step kind'", err)
	}
}

func TestDispatch_BOLA_RoutesToAPIModuleAndReturnsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	success, err := d.Dispatch(context.Background(), scenarios.StepSpec{
		Kind:   "bola",
		Params: map[string]any{"jwt": "test-jwt", "start_id": 1, "end_id": 1},
	}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success=true when target returns HTTP 200 for BOLA probe")
	}
}

func TestDispatch_SynFlood_InvalidTargetURL(t *testing.T) {
	d := NewDispatcher()
	_, err := d.Dispatch(context.Background(), scenarios.StepSpec{Kind: "syn_flood"}, "/no-host")
	if err == nil {
		t.Fatal("expected error for syn_flood with no host in target URL")
	}
	if !strings.Contains(err.Error(), "dispatch: syn_flood") {
		t.Errorf("error = %v, want wrapped with 'dispatch: syn_flood'", err)
	}
}

func TestDispatch_PortScan_InvalidTargetURL(t *testing.T) {
	d := NewDispatcher()
	_, err := d.Dispatch(context.Background(), scenarios.StepSpec{Kind: "port_scan"}, "not a url \x7f")
	if err == nil {
		t.Fatal("expected error for port_scan with unparseable target URL")
	}
}
