package config

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// setupViper wires viper with the same env prefix and replacer used by the
// real application (defined in cmd/apiguard/commands/root.go).
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
