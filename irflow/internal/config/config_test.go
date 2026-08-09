package config

import (
	"os"
	"testing"
	"time"
)

// TestLoad_Defaults verifies that Load() populates every documented default
// when no config file and no environment variables are present.
func TestLoad_Defaults(t *testing.T) {
	clearIRFlowEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host = %q, want %q", cfg.Server.Host, "0.0.0.0")
	}
	if cfg.Server.Port != 8083 {
		t.Errorf("Server.Port = %d, want 8083", cfg.Server.Port)
	}
	if cfg.Server.ReadTimeout != 15*time.Second {
		t.Errorf("Server.ReadTimeout = %v, want 15s", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 15*time.Second {
		t.Errorf("Server.WriteTimeout = %v, want 15s", cfg.Server.WriteTimeout)
	}

	if cfg.DB.Host != "localhost" {
		t.Errorf("DB.Host = %q, want %q", cfg.DB.Host, "localhost")
	}
	if cfg.DB.Port != 5432 {
		t.Errorf("DB.Port = %d, want 5432", cfg.DB.Port)
	}
	if cfg.DB.Name != "irflow" {
		t.Errorf("DB.Name = %q, want %q", cfg.DB.Name, "irflow")
	}
	if cfg.DB.SSLMode != "disable" {
		t.Errorf("DB.SSLMode = %q, want %q", cfg.DB.SSLMode, "disable")
	}

	if cfg.Citadel.APIURL != "http://localhost:8082" {
		t.Errorf("Citadel.APIURL = %q, want %q", cfg.Citadel.APIURL, "http://localhost:8082")
	}
	if !cfg.Citadel.DryRun {
		t.Error("Citadel.DryRun should default to true")
	}

	if cfg.NIS2.APIURL != "http://localhost:8081" {
		t.Errorf("NIS2.APIURL = %q, want %q", cfg.NIS2.APIURL, "http://localhost:8081")
	}
	if cfg.NIS2.MeasureRef != "b" {
		t.Errorf("NIS2.MeasureRef = %q, want %q (Article 21(2)(b))", cfg.NIS2.MeasureRef, "b")
	}

	if cfg.Auth.TokenTTL != 8*time.Hour {
		t.Errorf("Auth.TokenTTL = %v, want 8h", cfg.Auth.TokenTTL)
	}
	if cfg.Auth.Issuer != "irflow" {
		t.Errorf("Auth.Issuer = %q, want %q", cfg.Auth.Issuer, "irflow")
	}
	if cfg.Auth.DevMode {
		t.Error("Auth.DevMode should default to false")
	}
	if cfg.Auth.SinauthURL != "http://localhost:8100" {
		t.Errorf("Auth.SinauthURL = %q, want %q", cfg.Auth.SinauthURL, "http://localhost:8100")
	}

	if cfg.Webhook.MaxBodySize != 1<<20 {
		t.Errorf("Webhook.MaxBodySize = %d, want %d", cfg.Webhook.MaxBodySize, 1<<20)
	}
	if cfg.Webhook.ClockSkewTolerance != 5*time.Minute {
		t.Errorf("Webhook.ClockSkewTolerance = %v, want 5m", cfg.Webhook.ClockSkewTolerance)
	}
}

// TestLoad_EnvOverride confirms environment variables (IRFLOW_-prefixed,
// dot-to-underscore mapped) override the built-in defaults.
func TestLoad_EnvOverride(t *testing.T) {
	clearIRFlowEnv(t)

	t.Setenv("IRFLOW_SERVER_PORT", "9090")
	t.Setenv("IRFLOW_DB_HOST", "db.internal")
	t.Setenv("IRFLOW_AUTH_DEV_MODE", "true")
	t.Setenv("IRFLOW_AUTH_SECRET", "s3cr3t-from-env")
	t.Setenv("IRFLOW_WEBHOOK_APIGUARD_SECRET", "apiguard-secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090 (env override)", cfg.Server.Port)
	}
	if cfg.DB.Host != "db.internal" {
		t.Errorf("DB.Host = %q, want %q (env override)", cfg.DB.Host, "db.internal")
	}
	if !cfg.Auth.DevMode {
		t.Error("Auth.DevMode should be true (env override)")
	}
	if cfg.Auth.Secret != "s3cr3t-from-env" {
		t.Errorf("Auth.Secret = %q, want %q (env override)", cfg.Auth.Secret, "s3cr3t-from-env")
	}
	if cfg.Webhook.APIGuardSecret != "apiguard-secret" {
		t.Errorf("Webhook.APIGuardSecret = %q, want %q (env override)", cfg.Webhook.APIGuardSecret, "apiguard-secret")
	}
}

// TestWebhookConfig_ResolvedSecret_PerSourcePrecedence verifies each known
// source prefers its dedicated secret over the shared fallback.
func TestWebhookConfig_ResolvedSecret_PerSourcePrecedence(t *testing.T) {
	w := WebhookConfig{
		Secret:           "shared",
		APIGuardSecret:   "apiguard-only",
		CITADELSecret:    "citadel-only",
		ThreatFlowSecret: "threatflow-only",
		CyberPathSecret:  "cyberpath-only",
	}

	cases := []struct {
		source string
		want   string
	}{
		{"apiguard", "apiguard-only"},
		{"citadel", "citadel-only"},
		{"threatflow", "threatflow-only"},
		{"cyberpath", "cyberpath-only"},
		{"unknown-source", "shared"},
	}
	for _, c := range cases {
		if got := w.ResolvedSecret(c.source); got != c.want {
			t.Errorf("ResolvedSecret(%q) = %q, want %q", c.source, got, c.want)
		}
	}
}

// TestWebhookConfig_ResolvedSecret_FallsBackWhenPerSourceEmpty verifies that
// an empty per-source secret falls back to the shared secret rather than
// returning "" (which would incorrectly look like "no secret configured").
func TestWebhookConfig_ResolvedSecret_FallsBackWhenPerSourceEmpty(t *testing.T) {
	w := WebhookConfig{Secret: "shared-fallback"}

	for _, source := range []string{"apiguard", "citadel", "threatflow", "cyberpath"} {
		if got := w.ResolvedSecret(source); got != "shared-fallback" {
			t.Errorf("ResolvedSecret(%q) = %q, want %q", source, got, "shared-fallback")
		}
	}
}

// TestWebhookConfig_ResolvedSecret_EmptyMeansUnconfigured verifies that when
// neither a per-source nor shared secret is set, ResolvedSecret returns ""
// — the signal the webhook handlers use to reject all requests as 503.
func TestWebhookConfig_ResolvedSecret_EmptyMeansUnconfigured(t *testing.T) {
	var w WebhookConfig
	if got := w.ResolvedSecret("apiguard"); got != "" {
		t.Errorf("ResolvedSecret(%q) = %q, want empty string", "apiguard", got)
	}
}

// clearIRFlowEnv removes every IRFLOW_-prefixed environment variable for the
// duration of the test so Load() tests are hermetic regardless of the host
// shell's environment, restoring the original values afterwards.
func clearIRFlowEnv(t *testing.T) {
	t.Helper()
	const prefix = "IRFLOW_"
	var saved []string
	for _, kv := range os.Environ() {
		if len(kv) > len(prefix) && kv[:len(prefix)] == prefix {
			saved = append(saved, kv)
		}
	}
	for _, kv := range saved {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				key := kv[:i]
				val := kv[i+1:]
				os.Unsetenv(key)
				t.Cleanup(func() { os.Setenv(key, val) })
				break
			}
		}
	}
}
