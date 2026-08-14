package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCheckHealth_OK proves checkHealth accepts a 200 response from
// /api/v1/health as healthy.
func TestCheckHealth_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health" {
			t.Errorf("request path = %q, want /api/v1/health", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 4 * time.Second}
	addr := strings.TrimPrefix(srv.URL, "http://")
	if err := checkHealth(client, addr); err != nil {
		t.Fatalf("checkHealth: %v", err)
	}
}

// TestCheckHealth_NonOKStatus proves a non-200 response is reported as an
// error naming the actual status code, not silently treated as healthy.
func TestCheckHealth_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 4 * time.Second}
	addr := strings.TrimPrefix(srv.URL, "http://")
	err := checkHealth(client, addr)
	if err == nil {
		t.Fatal("checkHealth: expected error for 503 response, got nil")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("checkHealth error = %q, want it to mention 503", err.Error())
	}
}

// TestCheckHealth_ConnectionFailure proves an unreachable address surfaces
// as an error rather than panicking or hanging — checkHealth is what
// healthCmd's RunE uses to decide whether to os.Exit(1).
func TestCheckHealth_ConnectionFailure(t *testing.T) {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	// Port 1 is a reserved, always-refused-or-filtered port; a closed
	// server on the loopback interface (Close()d before calling) is more
	// deterministic across platforms, so use that instead.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close() // now nothing is listening on addr

	err := checkHealth(client, addr)
	if err == nil {
		t.Fatal("checkHealth: expected error for unreachable server, got nil")
	}
	if !strings.Contains(err.Error(), "health check failed") {
		t.Errorf("checkHealth error = %q, want it to mention 'health check failed'", err.Error())
	}
}

// TestHealthCmd_FlagDefault proves the --addr flag defaults to
// localhost:8100, matching sinauth's documented default HTTP port.
func TestHealthCmd_FlagDefault(t *testing.T) {
	f := healthCmd.Flags().Lookup("addr")
	if f == nil {
		t.Fatal("healthCmd is missing the --addr flag")
	}
	if f.DefValue != "localhost:8100" {
		t.Errorf("--addr default = %q, want localhost:8100", f.DefValue)
	}
}
