package config

import (
	"testing"

	"github.com/spf13/viper"
)

// resetViper clears any keys set by a previous test so each test observes a
// clean default set. viper is a package-level global, so tests in this file
// must not run in parallel with each other.
func resetViper() {
	for _, k := range []string{
		"port", "log_level", "db.url", "db.max_open_conns", "db.max_idle_conns",
		"citadel.api_url", "citadel.project_id", "citadel.fail_closed",
		"auth.jwt_secret", "auth.ttl_minutes", "auth.bootstrap_keys", "auth.sinauth_url",
		"cache.redis_url", "cache.ttl_seconds", "rate.requests_per_sec", "rate.burst",
	} {
		viper.Set(k, nil)
	}
}

func TestLoad_AppliesDocumentedDefaults(t *testing.T) {
	resetViper()
	cfg := Load()

	if cfg.Port != 8091 {
		t.Errorf("Port = %d, want 8091", cfg.Port)
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
	// citadel.fail_closed must default to true — this is a documented safety
	// property (fail-closed governance), regressing it to false would be a
	// real security defect, not just a config nit.
	if !cfg.Citadel.FailClosed {
		t.Error("Citadel.FailClosed must default to true (fail-closed)")
	}
	if cfg.Citadel.ProjectID != "threatflow" {
		t.Errorf("Citadel.ProjectID = %q, want %q", cfg.Citadel.ProjectID, "threatflow")
	}
	if cfg.Auth.TTLMinutes != 60 {
		t.Errorf("Auth.TTLMinutes = %d, want 60", cfg.Auth.TTLMinutes)
	}
	if cfg.Auth.SinauthURL != "http://localhost:8100" {
		t.Errorf("Auth.SinauthURL = %q, want default sinauth URL", cfg.Auth.SinauthURL)
	}
	if cfg.Cache.RedisURL != "" {
		t.Errorf("Cache.RedisURL = %q, want empty default", cfg.Cache.RedisURL)
	}
	if cfg.Cache.TTLSeconds != 600 {
		t.Errorf("Cache.TTLSeconds = %d, want 600", cfg.Cache.TTLSeconds)
	}
	if cfg.Rate.RequestsPerSec != 50.0 {
		t.Errorf("Rate.RequestsPerSec = %v, want 50.0", cfg.Rate.RequestsPerSec)
	}
	if cfg.Rate.Burst != 100 {
		t.Errorf("Rate.Burst = %d, want 100", cfg.Rate.Burst)
	}
}

// TestLoad_ExplicitValuesOverrideDefaults proves Load actually reads from
// viper rather than hardcoding the defaults it sets — the failure mode this
// guards against is a Load() that ignores operator-supplied configuration
// (e.g. env vars, config file) entirely.
func TestLoad_ExplicitValuesOverrideDefaults(t *testing.T) {
	resetViper()
	viper.Set("port", 9999)
	viper.Set("citadel.fail_closed", false)
	viper.Set("auth.bootstrap_keys", []string{"k1", "k2"})
	defer resetViper()

	cfg := Load()

	if cfg.Port != 9999 {
		t.Errorf("Port = %d, want 9999 (explicit override)", cfg.Port)
	}
	if cfg.Citadel.FailClosed {
		t.Error("Citadel.FailClosed override to false was not honoured")
	}
	if len(cfg.Auth.BootstrapKeys) != 2 || cfg.Auth.BootstrapKeys[0] != "k1" {
		t.Errorf("Auth.BootstrapKeys = %v, want [k1 k2]", cfg.Auth.BootstrapKeys)
	}
}
