// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionDetector_Run_BlocksPublicTarget(t *testing.T) {
	v := NewVersionDetector()
	_, err := v.Run(context.Background(), "http://1.1.1.1", nil)
	if err == nil {
		t.Fatal("expected error for public target")
	}
}

func TestVersionDetector_Run_DetectsServerHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	v := NewVersionDetector()
	result, err := v.Run(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when Server header is disclosed")
	}
	found := false
	for _, vi := range result.Versions {
		if vi.Name == "nginx" && vi.Version == "1.25.3" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected nginx/1.25.3 to be parsed, got %+v", result.Versions)
	}
}

func TestVersionDetector_Run_DetectsJSONVersionField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"3.2.1"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	v := NewVersionDetector()
	result, err := v.Run(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected Success=true when a version endpoint discloses JSON version")
	}
	found := false
	for _, vi := range result.Versions {
		if vi.Name == "version" && vi.Version == "3.2.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected version=3.2.1 to be found, got %+v", result.Versions)
	}
}

func TestVersionDetector_Run_NoDisclosure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	v := NewVersionDetector()
	result, err := v.Run(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false when nothing is disclosed")
	}
}

func TestParseSoftwareVersion_SlashFormat(t *testing.T) {
	var info VersionInfo
	parseSoftwareVersion("Apache/2.4.57", &info)
	if info.Name != "Apache" || info.Version != "2.4.57" {
		t.Errorf("got Name=%q Version=%q, want Apache 2.4.57", info.Name, info.Version)
	}
}

func TestParseSoftwareVersion_SpaceFormat(t *testing.T) {
	var info VersionInfo
	parseSoftwareVersion("Express 4.18", &info)
	if info.Name != "Express" || info.Version != "4.18" {
		t.Errorf("got Name=%q Version=%q, want Express 4.18", info.Name, info.Version)
	}
}

func TestParseSoftwareVersion_NoSeparator(t *testing.T) {
	var info VersionInfo
	parseSoftwareVersion("gunicorn", &info)
	if info.Name != "gunicorn" || info.Version != "" {
		t.Errorf("got Name=%q Version=%q, want gunicorn/empty", info.Name, info.Version)
	}
}

func TestContainsVersionSignal(t *testing.T) {
	if !containsVersionSignal("build 1234, commit abcd") {
		t.Error("expected signal to be detected")
	}
	if containsVersionSignal("nothing interesting here") {
		t.Error("expected no signal")
	}
}

func TestExtractJSONVersions_MultipleKeys(t *testing.T) {
	body := []byte(`{"version":"1.0","commit":"abc123","irrelevant":"x"}`)
	versions := extractJSONVersions(body, "/info")
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions extracted, got %d: %+v", len(versions), versions)
	}
}

func TestExtractJSONVersions_InvalidJSON(t *testing.T) {
	versions := extractJSONVersions([]byte("not json"), "/info")
	if versions != nil {
		t.Errorf("expected nil for invalid JSON, got %v", versions)
	}
}

func TestTruncate_ReconPackage(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("got %q, want unchanged", got)
	}
	if got := truncate("this is long", 4); got != "this…" {
		t.Errorf("got %q, want %q", got, "this…")
	}
}
