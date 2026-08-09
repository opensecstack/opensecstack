package config

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// setupViper wires viper with the same env prefix and replacer used by the
// real application (defined in setDefaults() in this package, and mirrored
// by initConfig() in cmd/apiguard/main.go for YAML file loading).
func setupViper() {
	viper.Reset()
	viper.SetEnvPrefix("APIGUARD")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
}

func TestLoad_WithEnvVars(t *testing.T) {
	setupViper()
	t.Setenv("APIGUARD_PORT", "9090")
	t.Setenv("APIGUARD_AUTH_JWT_SECRET", "mysecret")
	t.Setenv("APIGUARD_SCANNER_RATE_LIMIT", "200")

	cfg := Load()

	if cfg.Port != 9090 {
		t.Errorf("expected Port=9090, got %d", cfg.Port)
	}
	if cfg.Auth.JWTSecret != "mysecret" {
		t.Errorf("expected JWTSecret=mysecret, got %q", cfg.Auth.JWTSecret)
	}
	if cfg.Scanner.RateLimit != 200 {
		t.Errorf("expected RateLimit=200, got %d", cfg.Scanner.RateLimit)
	}
}

func TestLoad_Defaults(t *testing.T) {
	setupViper()

	cfg := Load()

	if cfg.Port != 8080 {
		t.Errorf("expected default Port=8080, got %d", cfg.Port)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel=info, got %q", cfg.LogLevel)
	}
	if cfg.DB.MaxOpenConns != 25 {
		t.Errorf("expected default DB.MaxOpenConns=25, got %d", cfg.DB.MaxOpenConns)
	}
	if cfg.Scanner.Timeout != 5*time.Minute {
		t.Errorf("expected default Scanner.Timeout=5m, got %v", cfg.Scanner.Timeout)
	}
}

func TestAuthConfig_String_WithSecret(t *testing.T) {
	a := AuthConfig{JWTSecret: "super-secret-value"}
	s := a.String()
	if !strings.Contains(s, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in String(), got %q", s)
	}
	if strings.Contains(s, "super-secret-value") {
		t.Errorf("String() must not contain the actual secret, got %q", s)
	}
}

func TestAuthConfig_String_EmptySecret(t *testing.T) {
	a := AuthConfig{JWTSecret: ""}
	s := a.String()
	if !strings.Contains(s, "[NOT SET]") {
		t.Errorf("expected [NOT SET] in String(), got %q", s)
	}
}

func TestEffectiveJWTSecrets_MultiSecretTakesPrecedence(t *testing.T) {
	a := AuthConfig{
		JWTSecrets:        []string{"key1", "key2", "key3"},
		JWTSecret:         "legacy",
		PreviousJWTSecret: "legacy-prev",
	}
	got := a.EffectiveJWTSecrets()
	want := []string{"key1", "key2", "key3"}
	if len(got) != len(want) {
		t.Fatalf("expected %d secrets, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("secret[%d]: expected %q, got %q", i, want[i], got[i])
		}
	}
}

func TestEffectiveJWTSecrets_LegacyTwoSlot(t *testing.T) {
	a := AuthConfig{
		JWTSecret:         "current",
		PreviousJWTSecret: "previous",
	}
	got := a.EffectiveJWTSecrets()
	want := []string{"current", "previous"}
	if len(got) != len(want) {
		t.Fatalf("expected %d secrets, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("secret[%d]: expected %q, got %q", i, want[i], got[i])
		}
	}
}

func TestEffectiveJWTSecrets_OnlyCurrentSecret(t *testing.T) {
	a := AuthConfig{JWTSecret: "only-one"}
	got := a.EffectiveJWTSecrets()
	if len(got) != 1 || got[0] != "only-one" {
		t.Errorf("expected [only-one], got %v", got)
	}
}

func TestEffectiveJWTSecrets_OnlyPreviousSetWithoutCurrent(t *testing.T) {
	// PreviousJWTSecret without JWTSecret is a degenerate config, but the
	// implementation still surfaces it as a single verification-only secret
	// rather than silently dropping it.
	a := AuthConfig{PreviousJWTSecret: "previous-only"}
	got := a.EffectiveJWTSecrets()
	if len(got) != 1 || got[0] != "previous-only" {
		t.Errorf("expected [previous-only], got %v", got)
	}
}

func TestEffectiveJWTSecrets_AllEmpty(t *testing.T) {
	a := AuthConfig{}
	got := a.EffectiveJWTSecrets()
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}

func TestWarnIfInsecure_DoesNotPanic(t *testing.T) {
	// WarnIfInsecure only logs; verify all branches execute without error
	// regardless of configuration state.
	c := &Config{}
	c.WarnIfInsecure() // TLSSkipVerify=false, JWTSecret="" -> warns about missing secret

	c2 := &Config{Scanner: ScannerConfig{TLSSkipVerify: true}, Auth: AuthConfig{JWTSecret: "set"}}
	c2.WarnIfInsecure() // TLSSkipVerify=true -> warns; JWTSecret set -> no warning

	c3 := &Config{Auth: AuthConfig{JWTSecret: "set"}}
	c3.WarnIfInsecure() // neither condition triggers a warning
}
