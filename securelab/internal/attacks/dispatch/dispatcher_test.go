// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package dispatch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestDispatch_MassAssignment_RoutesToAPIModule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"role":"admin"}`))
	}))
	defer server.Close()

	d := NewDispatcher()
	success, err := d.Dispatch(context.Background(), scenarios.StepSpec{
		Kind:   "mass_assignment",
		Params: map[string]any{"endpoints": []string{"/api/profile"}},
	}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success=true when server reflects a privileged field")
	}
}

func TestDispatch_SSRF_RoutesToAPIModule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := NewDispatcher()
	success, err := d.Dispatch(context.Background(), scenarios.StepSpec{
		Kind: "ssrf",
		Params: map[string]any{
			"endpoints":   []string{"/api/fetch"},
			"param_names": []string{"url"},
		},
	}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if success {
		t.Error("expected success=false when every SSRF probe 404s")
	}
}

// TestDispatch_Misconfig_RoutesToAPIModule uses a bare server that returns a
// plain 404 with no security headers on every path. Since the misconfig
// attack's "missing security headers" check (step 4) probes the base URL
// unconditionally, such a server is flagged as misconfigured even though it
// has no exposed debug endpoints or default credentials — this asserts that
// finding is what actually drives success=true here.
func TestDispatch_Misconfig_RoutesToAPIModule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := NewDispatcher()
	success, err := d.Dispatch(context.Background(), scenarios.StepSpec{
		Kind: "misconfig",
	}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success=true when the server is missing all required security headers")
	}
}

func TestDispatch_RateLimitBypass_RoutesToAPIModule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	d := NewDispatcher()
	success, err := d.Dispatch(context.Background(), scenarios.StepSpec{
		Kind:   "rate_limit_bypass",
		Params: map[string]any{"burst": 5, "concurrency": 2},
	}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if success {
		t.Error("expected success=false when every request is rate-limited")
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

func TestDispatch_AuthBypass_RoutesToAPIModuleAndReturnsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	success, err := d.Dispatch(context.Background(), scenarios.StepSpec{
		Kind:   "auth_bypass",
		Params: map[string]any{"endpoints": []string{"/api/admin"}},
	}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success=true when target accepts a forged token with HTTP 200")
	}
}

func TestDispatch_EndpointEnum_RoutesToReconModule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	d := NewDispatcher()
	success, err := d.Dispatch(context.Background(), scenarios.StepSpec{
		Kind:   "endpoint_enum",
		Params: map[string]any{"concurrency": 5},
	}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success=true when at least one wordlist endpoint is discovered")
	}
}

func TestDispatch_VersionDetect_RoutesToReconModule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	success, err := d.Dispatch(context.Background(), scenarios.StepSpec{
		Kind: "version_detect",
	}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success=true when the Server header discloses a version")
	}
}

func TestDispatch_DataExfil_RoutesToExfilModuleAndReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDispatcher()
	// Omitting the required "jwt" param exercises the module's own validation
	// (fast, no network I/O) while still confirming dispatch routes to it.
	_, err := d.Dispatch(context.Background(), scenarios.StepSpec{
		Kind: "data_exfil",
	}, server.URL)
	if err == nil {
		t.Fatal("expected error for data_exfil without required jwt param")
	}
	if !strings.Contains(err.Error(), "jwt") {
		t.Errorf("error = %v, want message mentioning missing jwt param", err)
	}
}

func TestDispatch_DNSTunnel_RoutesToExfilModuleAndReturnsError(t *testing.T) {
	d := NewDispatcher()
	// Omitting the required "dns_server" param exercises the module's own
	// validation (fast, no network I/O) while confirming dispatch routes to it.
	_, err := d.Dispatch(context.Background(), scenarios.StepSpec{
		Kind: "dns_tunnel",
	}, "http://127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected error for dns_tunnel without required dns_server param")
	}
	if !strings.Contains(err.Error(), "dns_server") {
		t.Errorf("error = %v, want message mentioning missing dns_server param", err)
	}
}

func TestDispatch_UDPFlood_InvalidTargetURL(t *testing.T) {
	d := NewDispatcher()
	_, err := d.Dispatch(context.Background(), scenarios.StepSpec{Kind: "udp_flood"}, "/no-host")
	if err == nil {
		t.Fatal("expected error for udp_flood with no host in target URL")
	}
	if !strings.Contains(err.Error(), "dispatch: udp_flood") {
		t.Errorf("error = %v, want wrapped with 'dispatch: udp_flood'", err)
	}
}

func TestDispatch_HTTPFlood_InvalidTargetURL(t *testing.T) {
	d := NewDispatcher()
	_, err := d.Dispatch(context.Background(), scenarios.StepSpec{Kind: "http_flood"}, "/no-host")
	if err == nil {
		t.Fatal("expected error for http_flood with no host in target URL")
	}
	if !strings.Contains(err.Error(), "dispatch: http_flood") {
		t.Errorf("error = %v, want wrapped with 'dispatch: http_flood'", err)
	}
}

func TestDispatch_Slowloris_InvalidTargetURL(t *testing.T) {
	d := NewDispatcher()
	_, err := d.Dispatch(context.Background(), scenarios.StepSpec{Kind: "slowloris"}, "/no-host")
	if err == nil {
		t.Fatal("expected error for slowloris with no host in target URL")
	}
	if !strings.Contains(err.Error(), "dispatch: slowloris") {
		t.Errorf("error = %v, want wrapped with 'dispatch: slowloris'", err)
	}
}

// TestDispatch_SynFlood_ImmediateContextCancellation exercises the syn_flood
// success path (splitNetworkTarget succeeds, Run is invoked) without waiting
// out the default 5s duration: an already-expired context makes Run's
// select loop hit ctx.Done() on its very first iteration.
func TestDispatch_SynFlood_ImmediateContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	d := NewDispatcher()
	_, err := d.Dispatch(ctx, scenarios.StepSpec{Kind: "syn_flood"}, "http://127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected context deadline exceeded error")
	}
}
