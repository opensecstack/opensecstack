// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/opensecstack/securelab/internal/config"
)

// clearEnv removes all SECURELAB_ env vars that FromEnv reads, so tests don't
// leak state into each other or pick up variables set in the host environment.
func clearEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"SECURELAB_HTTP_ADDR", "SECURELAB_DEV_MODE", "SECURELAB_DB_URL",
		"SECURELAB_DB_MAX_CONNS", "SECURELAB_JWT_SECRET", "SECURELAB_JWT_ISSUER",
		"SECURELAB_TOKEN_TTL", "SECURELAB_CITADEL_API_URL", "SECURELAB_CITADEL_HMAC_SECRETS",
		"SECURELAB_CITADEL_DRY_RUN", "SECURELAB_NODE", "SECURELAB_OUTBOX_TICK",
		"SECURELAB_MAX_CONCURRENT_SCENARIOS", "SECURELAB_SCENARIO_TIMEOUT", "SECURELAB_SINAUTH_URL",
	}
	for _, k := range keys {
		t.Cleanup(func(k string) func() { return func() { os.Unsetenv(k) } }(k))
		os.Unsetenv(k)
	}
}

func TestFromEnv_Defaults(t *testing.T) {
	clearEnv(t)

	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HTTPAddr != ":8085" {
		t.Errorf("HTTPAddr = %q, want :8085", cfg.HTTPAddr)
	}
	if cfg.DBMaxConns != 8 {
		t.Errorf("DBMaxConns = %d, want 8", cfg.DBMaxConns)
	}
	if cfg.JWTIssuer != "securelab" {
		t.Errorf("JWTIssuer = %q, want securelab", cfg.JWTIssuer)
	}
	if cfg.TokenTTL != 12*time.Hour {
		t.Errorf("TokenTTL = %v, want 12h", cfg.TokenTTL)
	}
	if !cfg.CitadelDryRun {
		t.Error("CitadelDryRun = false, want true")
	}
	if cfg.Node != "securelab-0" {
		t.Errorf("Node = %q, want securelab-0", cfg.Node)
	}
	if cfg.OutboxTick != 10*time.Second {
		t.Errorf("OutboxTick = %v, want 10s", cfg.OutboxTick)
	}
	if cfg.MaxConcurrentScenarios != 3 {
		t.Errorf("MaxConcurrentScenarios = %d, want 3", cfg.MaxConcurrentScenarios)
	}
	if cfg.ScenarioTimeout != 5*time.Minute {
		t.Errorf("ScenarioTimeout = %v, want 5m", cfg.ScenarioTimeout)
	}
	if cfg.SinauthURL != "http://localhost:8100" {
		t.Errorf("SinauthURL = %q, want http://localhost:8100", cfg.SinauthURL)
	}
	if cfg.DevMode {
		t.Error("DevMode = true, want false by default")
	}
}

func TestFromEnv_OverridesFromEnvironment(t *testing.T) {
	clearEnv(t)

	os.Setenv("SECURELAB_HTTP_ADDR", ":9999")
	os.Setenv("SECURELAB_DEV_MODE", "true")
	os.Setenv("SECURELAB_DB_URL", "postgres://x")
	os.Setenv("SECURELAB_DB_MAX_CONNS", "16")
	os.Setenv("SECURELAB_JWT_SECRET", "s3cr3t")
	os.Setenv("SECURELAB_JWT_ISSUER", "custom-issuer")
	os.Setenv("SECURELAB_TOKEN_TTL", "1h")
	os.Setenv("SECURELAB_CITADEL_API_URL", "http://citadel")
	os.Setenv("SECURELAB_CITADEL_HMAC_SECRETS", "a, b ,,c")
	os.Setenv("SECURELAB_CITADEL_DRY_RUN", "false")
	os.Setenv("SECURELAB_NODE", "node-7")
	os.Setenv("SECURELAB_OUTBOX_TICK", "30s")
	os.Setenv("SECURELAB_MAX_CONCURRENT_SCENARIOS", "9")
	os.Setenv("SECURELAB_SCENARIO_TIMEOUT", "2m")
	os.Setenv("SECURELAB_SINAUTH_URL", "http://sinauth.example")

	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.HTTPAddr != ":9999" {
		t.Errorf("HTTPAddr = %q", cfg.HTTPAddr)
	}
	if !cfg.DevMode {
		t.Error("DevMode should be true")
	}
	if cfg.DBUrl != "postgres://x" {
		t.Errorf("DBUrl = %q", cfg.DBUrl)
	}
	if cfg.DBMaxConns != 16 {
		t.Errorf("DBMaxConns = %d", cfg.DBMaxConns)
	}
	if cfg.JWTSecret != "s3cr3t" {
		t.Errorf("JWTSecret = %q", cfg.JWTSecret)
	}
	if cfg.JWTIssuer != "custom-issuer" {
		t.Errorf("JWTIssuer = %q", cfg.JWTIssuer)
	}
	if cfg.TokenTTL != time.Hour {
		t.Errorf("TokenTTL = %v", cfg.TokenTTL)
	}
	if cfg.CitadelAPIURL != "http://citadel" {
		t.Errorf("CitadelAPIURL = %q", cfg.CitadelAPIURL)
	}
	wantSecrets := []string{"a", "b", "c"}
	if len(cfg.CitadelHMACSecrets) != len(wantSecrets) {
		t.Fatalf("CitadelHMACSecrets = %v, want %v", cfg.CitadelHMACSecrets, wantSecrets)
	}
	for i, s := range wantSecrets {
		if cfg.CitadelHMACSecrets[i] != s {
			t.Errorf("CitadelHMACSecrets[%d] = %q, want %q", i, cfg.CitadelHMACSecrets[i], s)
		}
	}
	if cfg.CitadelDryRun {
		t.Error("CitadelDryRun should be false")
	}
	if cfg.Node != "node-7" {
		t.Errorf("Node = %q", cfg.Node)
	}
	if cfg.OutboxTick != 30*time.Second {
		t.Errorf("OutboxTick = %v", cfg.OutboxTick)
	}
	if cfg.MaxConcurrentScenarios != 9 {
		t.Errorf("MaxConcurrentScenarios = %d", cfg.MaxConcurrentScenarios)
	}
	if cfg.ScenarioTimeout != 2*time.Minute {
		t.Errorf("ScenarioTimeout = %v", cfg.ScenarioTimeout)
	}
	if cfg.SinauthURL != "http://sinauth.example" {
		t.Errorf("SinauthURL = %q", cfg.SinauthURL)
	}
}

func TestFromEnv_InvalidDevMode(t *testing.T) {
	clearEnv(t)
	os.Setenv("SECURELAB_DEV_MODE", "not-a-bool")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error for invalid DEV_MODE")
	}
}

func TestFromEnv_InvalidDBMaxConns(t *testing.T) {
	clearEnv(t)
	os.Setenv("SECURELAB_DB_MAX_CONNS", "not-a-number")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error for invalid DB_MAX_CONNS")
	}
}

func TestFromEnv_NonPositiveDBMaxConns(t *testing.T) {
	clearEnv(t)
	os.Setenv("SECURELAB_DB_MAX_CONNS", "0")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error for zero DB_MAX_CONNS")
	}
}

func TestFromEnv_InvalidTokenTTL(t *testing.T) {
	clearEnv(t)
	os.Setenv("SECURELAB_TOKEN_TTL", "not-a-duration")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error for invalid TOKEN_TTL")
	}
}

func TestFromEnv_InvalidCitadelDryRun(t *testing.T) {
	clearEnv(t)
	os.Setenv("SECURELAB_CITADEL_DRY_RUN", "not-a-bool")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error for invalid CITADEL_DRY_RUN")
	}
}

func TestFromEnv_InvalidOutboxTick(t *testing.T) {
	clearEnv(t)
	os.Setenv("SECURELAB_OUTBOX_TICK", "not-a-duration")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error for invalid OUTBOX_TICK")
	}
}

func TestFromEnv_InvalidMaxConcurrentScenarios(t *testing.T) {
	clearEnv(t)
	os.Setenv("SECURELAB_MAX_CONCURRENT_SCENARIOS", "-1")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error for negative MAX_CONCURRENT_SCENARIOS")
	}
}

func TestFromEnv_InvalidScenarioTimeout(t *testing.T) {
	clearEnv(t)
	os.Setenv("SECURELAB_SCENARIO_TIMEOUT", "not-a-duration")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error for invalid SCENARIO_TIMEOUT")
	}
}

// ---------------------------------------------------------------------------
// Validate tests
// ---------------------------------------------------------------------------

func TestValidate_MissingDBUrl(t *testing.T) {
	cfg := &config.Config{DevMode: true}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing DBUrl")
	}
}

func TestValidate_DevModeSkipsStrictChecks(t *testing.T) {
	cfg := &config.Config{DevMode: true, DBUrl: "postgres://x"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error in dev mode with DBUrl set, got: %v", err)
	}
}

func TestValidate_ProductionRequiresLongJWTSecret(t *testing.T) {
	cfg := &config.Config{DevMode: false, DBUrl: "postgres://x", JWTSecret: "short", CitadelDryRun: true}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for short JWT secret in production mode")
	}
}

func TestValidate_ProductionRequiresHMACSecretsWhenNotDryRun(t *testing.T) {
	cfg := &config.Config{
		DevMode:       false,
		DBUrl:         "postgres://x",
		JWTSecret:     "01234567890123456789012345678901", // 34 bytes, >= 32
		CitadelDryRun: false,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing CitadelHMACSecrets when CitadelDryRun=false")
	}
}

func TestValidate_ProductionValidConfig(t *testing.T) {
	cfg := &config.Config{
		DevMode:            false,
		DBUrl:              "postgres://x",
		JWTSecret:          "01234567890123456789012345678901",
		CitadelDryRun:      false,
		CitadelHMACSecrets: []string{"secret1"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no error for valid production config, got: %v", err)
	}
}

func TestValidate_MultipleErrorsJoined(t *testing.T) {
	cfg := &config.Config{DevMode: false} // missing DBUrl and short JWTSecret
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	// Both distinct problems should be reported.
	msg := err.Error()
	if !contains(msg, "DB_URL") || !contains(msg, "JWT_SECRET") {
		t.Errorf("expected combined error to mention both DB_URL and JWT_SECRET, got: %s", msg)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}
