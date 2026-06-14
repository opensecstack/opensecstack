package config

import (
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.HTTPAddr != ":8086" {
		t.Errorf("server.http_addr = %q, want :8086", cfg.Server.HTTPAddr)
	}
	if cfg.DB.Port != 5439 {
		t.Errorf("db.port = %d, want 5439", cfg.DB.Port)
	}
	if cfg.Auth.Issuer != "cyberpath" {
		t.Errorf("auth.issuer = %q, want cyberpath", cfg.Auth.Issuer)
	}
	if cfg.I18n.Default != "sq" {
		t.Errorf("i18n.default = %q, want sq", cfg.I18n.Default)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("CYBERPATH_SERVER_HTTP_ADDR", ":9999")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.HTTPAddr != ":9999" {
		t.Errorf("server.http_addr = %q, want :9999", cfg.Server.HTTPAddr)
	}
}

func TestValidateProductionFailsWithoutSecret(t *testing.T) {
	t.Setenv("CYBERPATH_ENV", "production")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Auth.Secret = ""
	cfg.DB.SSLMode = "disable"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Validate to fail in prod with empty secret + disable sslmode")
	}
}

func TestActiveSecretsOrder(t *testing.T) {
	a := AuthConfig{Secret: "p", SecretNext: "n", SecretPrevious: "o"}
	got := a.ActiveSecrets()
	want := []string{"p", "n", "o"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("idx %d = %q, want %q", i, got[i], want[i])
		}
	}
}
