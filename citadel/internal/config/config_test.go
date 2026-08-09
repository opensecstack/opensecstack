package config

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// resetViper clears global viper state between tests — Load()/setDefaults()
// mutate the package-level viper.GetViper() singleton, so tests must not
// leak defaults/env bindings into each other.
func resetViper(t *testing.T) {
	t.Helper()
	viper.Reset()
}

func TestLoad_Defaults(t *testing.T) {
	resetViper(t)
	cfg := Load()

	if cfg.Port != 8099 {
		t.Errorf("Port = %d, want 8099", cfg.Port)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.DB.MaxOpenConns != 25 {
		t.Errorf("DB.MaxOpenConns = %d, want 25", cfg.DB.MaxOpenConns)
	}
	if cfg.DB.MaxIdleConns != 5 {
		t.Errorf("DB.MaxIdleConns = %d, want 5", cfg.DB.MaxIdleConns)
	}
	if cfg.DB.ConnMaxLifetime != 5*time.Minute {
		t.Errorf("DB.ConnMaxLifetime = %v, want 5m", cfg.DB.ConnMaxLifetime)
	}
	if cfg.Citadel.AnchorInterval != 100 {
		t.Errorf("Citadel.AnchorInterval = %d, want 100", cfg.Citadel.AnchorInterval)
	}
	if cfg.Citadel.GenesisHash != "b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a15" {
		t.Errorf("Citadel.GenesisHash = %q, unexpected", cfg.Citadel.GenesisHash)
	}
	if cfg.Citadel.EnforceIdentity {
		t.Error("Citadel.EnforceIdentity should default to false")
	}
	if cfg.Citadel.EnforceSignatures {
		t.Error("Citadel.EnforceSignatures should default to false")
	}
	if cfg.Citadel.EnforcePermifyAuthz {
		t.Error("Citadel.EnforcePermifyAuthz should default to false")
	}
	if cfg.Citadel.PermifySyncInterval != 5*time.Minute {
		t.Errorf("Citadel.PermifySyncInterval = %v, want 5m", cfg.Citadel.PermifySyncInterval)
	}
}

// TestLoad_EnvOverrides exercises the single-prefixed CITADEL_* env var
// bindings explicitly set up in setDefaults (the workaround for viper's
// AutomaticEnv double-prefixing "citadel.*" keys — see the comment above
// those BindEnv calls). Without these explicit bindings, none of these env
// vars would be picked up.
func TestLoad_EnvOverrides(t *testing.T) {
	resetViper(t)
	t.Setenv("CITADEL_MASTER_KEY", "deadbeef")
	t.Setenv("CITADEL_ANCHOR_INTERVAL", "42")
	t.Setenv("CITADEL_GENESIS_HASH", "customhash")
	t.Setenv("CITADEL_ENFORCE_IDENTITY", "true")
	t.Setenv("CITADEL_ENFORCE_SIGNATURES", "true")
	t.Setenv("CITADEL_SINAUTH_ISSUER_URL", "https://auth.sin.to")
	t.Setenv("CITADEL_PERMIFY_URL", "https://permify.sin.to")
	t.Setenv("CITADEL_ENFORCE_PERMIFY_AUTHZ", "true")
	t.Setenv("CITADEL_PERMIFY_SYNC_INTERVAL", "10m")
	t.Setenv("CITADEL_PORT", "9000")
	t.Setenv("CITADEL_DB_URL", "postgres://x")

	cfg := Load()

	if cfg.Port != 9000 {
		t.Errorf("Port = %d, want 9000", cfg.Port)
	}
	if cfg.DB.URL != "postgres://x" {
		t.Errorf("DB.URL = %q, want %q", cfg.DB.URL, "postgres://x")
	}
	if cfg.Citadel.MasterKey != "deadbeef" {
		t.Errorf("Citadel.MasterKey = %q, want %q", cfg.Citadel.MasterKey, "deadbeef")
	}
	if cfg.Citadel.AnchorInterval != 42 {
		t.Errorf("Citadel.AnchorInterval = %d, want 42", cfg.Citadel.AnchorInterval)
	}
	if cfg.Citadel.GenesisHash != "customhash" {
		t.Errorf("Citadel.GenesisHash = %q, want %q", cfg.Citadel.GenesisHash, "customhash")
	}
	if !cfg.Citadel.EnforceIdentity {
		t.Error("Citadel.EnforceIdentity should be true")
	}
	if !cfg.Citadel.EnforceSignatures {
		t.Error("Citadel.EnforceSignatures should be true")
	}
	if cfg.Citadel.SinauthIssuerURL != "https://auth.sin.to" {
		t.Errorf("Citadel.SinauthIssuerURL = %q, unexpected", cfg.Citadel.SinauthIssuerURL)
	}
	if cfg.Citadel.PermifyURL != "https://permify.sin.to" {
		t.Errorf("Citadel.PermifyURL = %q, unexpected", cfg.Citadel.PermifyURL)
	}
	if !cfg.Citadel.EnforcePermifyAuthz {
		t.Error("Citadel.EnforcePermifyAuthz should be true")
	}
	if cfg.Citadel.PermifySyncInterval != 10*time.Minute {
		t.Errorf("Citadel.PermifySyncInterval = %v, want 10m", cfg.Citadel.PermifySyncInterval)
	}
}

func TestWarnIfInsecure_NoOutputWhenConfigured(t *testing.T) {
	cfg := &Config{
		DB:      DatabaseConfig{URL: "postgres://x"},
		Citadel: CitadelConfig{MasterKey: "deadbeef"},
	}
	out := captureLog(t, cfg.WarnIfInsecure)
	if out != "" {
		t.Errorf("expected no warnings when fully configured, got: %q", out)
	}
}

func TestWarnIfInsecure_WarnsOnMissingDBURL(t *testing.T) {
	cfg := &Config{
		DB:      DatabaseConfig{URL: ""},
		Citadel: CitadelConfig{MasterKey: "deadbeef"},
	}
	out := captureLog(t, cfg.WarnIfInsecure)
	if !contains(out, "CITADEL_DB_URL is not set") {
		t.Errorf("expected DB URL warning, got: %q", out)
	}
}

func TestWarnIfInsecure_WarnsOnMissingMasterKey(t *testing.T) {
	cfg := &Config{
		DB:      DatabaseConfig{URL: "postgres://x"},
		Citadel: CitadelConfig{MasterKey: ""},
	}
	out := captureLog(t, cfg.WarnIfInsecure)
	if !contains(out, "CITADEL_MASTER_KEY is not set") {
		t.Errorf("expected master key warning, got: %q", out)
	}
}

// captureLog redirects the standard log package's output for the duration
// of fn and returns what was written.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	log.SetOutput(w)
	defer log.SetOutput(os.Stderr)

	fn()
	_ = w.Close()

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	_ = r.Close()
	return string(buf[:n])
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
