package config

import (
	"strings"
	"testing"
	"time"
)

// clearRequiredEnv ensures a clean slate for the required-in-prod variables
// each test setenv-clears, so tests don't depend on ambient environment
// state from the CI/dev machine running them.
func clearRequiredEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SINAUTH_DEV_MODE", "SINAUTH_DB_URL", "SINAUTH_ISSUER", "SINAUTH_SIGNING_KEY_PATH",
	} {
		t.Setenv(k, "")
	}
}

func TestLoad_DevModeSkipsRequiredValidation(t *testing.T) {
	clearRequiredEnv(t)
	t.Setenv("SINAUTH_DEV_MODE", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: unexpected error in dev mode with no required vars set: %v", err)
	}
	if !cfg.DevMode {
		t.Error("DevMode = false, want true")
	}
}

func TestLoad_ProdModeRequiresFields(t *testing.T) {
	clearRequiredEnv(t)
	// DevMode left unset (false).

	_, err := Load()
	if err == nil {
		t.Fatal("Load: expected error for missing required fields outside dev mode, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"SINAUTH_DB_URL", "SINAUTH_ISSUER", "SINAUTH_SIGNING_KEY_PATH"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Load error %q should mention missing %s", msg, want)
		}
	}
}

func TestLoad_ProdModeSucceedsWithAllRequiredFields(t *testing.T) {
	clearRequiredEnv(t)
	t.Setenv("SINAUTH_DB_URL", "postgres://localhost/sinauth")
	t.Setenv("SINAUTH_ISSUER", "https://auth.sin.to")
	t.Setenv("SINAUTH_SIGNING_KEY_PATH", "/etc/sinauth/key.pem")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: unexpected error with all required fields set: %v", err)
	}
	if cfg.DBURL != "postgres://localhost/sinauth" {
		t.Errorf("DBURL = %q, want postgres://localhost/sinauth", cfg.DBURL)
	}
	if cfg.Issuer != "https://auth.sin.to" {
		t.Errorf("Issuer = %q, want https://auth.sin.to", cfg.Issuer)
	}
}

func TestLoad_SocialRedirectURIsDefaultFromIssuer(t *testing.T) {
	clearRequiredEnv(t)
	t.Setenv("SINAUTH_DEV_MODE", "true")
	t.Setenv("SINAUTH_ISSUER", "https://auth.sin.to/")
	t.Setenv("GOOGLE_REDIRECT_URI", "")
	t.Setenv("GITHUB_REDIRECT_URI", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GoogleRedirectURI != "https://auth.sin.to/api/v1/auth/google/callback" {
		t.Errorf("GoogleRedirectURI = %q, want the derived callback URL", cfg.GoogleRedirectURI)
	}
	if cfg.GitHubRedirectURI != "https://auth.sin.to/api/v1/auth/github/callback" {
		t.Errorf("GitHubRedirectURI = %q, want the derived callback URL", cfg.GitHubRedirectURI)
	}
}

func TestLoad_ExplicitSocialRedirectURINotOverridden(t *testing.T) {
	clearRequiredEnv(t)
	t.Setenv("SINAUTH_DEV_MODE", "true")
	t.Setenv("SINAUTH_ISSUER", "https://auth.sin.to")
	t.Setenv("GOOGLE_REDIRECT_URI", "https://custom.example.com/cb")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GoogleRedirectURI != "https://custom.example.com/cb" {
		t.Errorf("GoogleRedirectURI = %q, want the explicitly configured value preserved", cfg.GoogleRedirectURI)
	}
}

func TestLoad_WebAuthnOriginsDefaultAndOverride(t *testing.T) {
	clearRequiredEnv(t)
	t.Setenv("SINAUTH_DEV_MODE", "true")
	t.Setenv("SINAUTH_WEBAUTHN_ORIGINS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.WebAuthnOrigins) != 1 || cfg.WebAuthnOrigins[0] != "http://localhost:5173" {
		t.Errorf("WebAuthnOrigins default = %v, want [http://localhost:5173]", cfg.WebAuthnOrigins)
	}

	t.Setenv("SINAUTH_WEBAUTHN_ORIGINS", "https://a.example, https://b.example")
	cfg2, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"https://a.example", "https://b.example"}
	if len(cfg2.WebAuthnOrigins) != 2 || cfg2.WebAuthnOrigins[0] != want[0] || cfg2.WebAuthnOrigins[1] != want[1] {
		t.Errorf("WebAuthnOrigins = %v, want %v (trimmed)", cfg2.WebAuthnOrigins, want)
	}
}

func TestEnv_FallbackWhenUnset(t *testing.T) {
	t.Setenv("SINAUTH_TEST_ENV_KEY", "")
	if got := env("SINAUTH_TEST_ENV_KEY", "fallback"); got != "fallback" {
		t.Errorf("env() = %q, want fallback", got)
	}
}

func TestEnv_UsesSetValue(t *testing.T) {
	t.Setenv("SINAUTH_TEST_ENV_KEY", "explicit")
	if got := env("SINAUTH_TEST_ENV_KEY", "fallback"); got != "explicit" {
		t.Errorf("env() = %q, want explicit", got)
	}
}

func TestEnvInt_ParsesOrFallsBack(t *testing.T) {
	t.Setenv("SINAUTH_TEST_INT_KEY", "42")
	if got := envInt("SINAUTH_TEST_INT_KEY", 7); got != 42 {
		t.Errorf("envInt() = %d, want 42", got)
	}

	t.Setenv("SINAUTH_TEST_INT_KEY", "not-a-number")
	if got := envInt("SINAUTH_TEST_INT_KEY", 7); got != 7 {
		t.Errorf("envInt() with invalid value = %d, want fallback 7", got)
	}

	t.Setenv("SINAUTH_TEST_INT_KEY", "")
	if got := envInt("SINAUTH_TEST_INT_KEY", 7); got != 7 {
		t.Errorf("envInt() with unset value = %d, want fallback 7", got)
	}
}

func TestEnvBool_TruthyValues(t *testing.T) {
	for _, v := range []string{"true", "1", "yes", "TRUE", "Yes"} {
		t.Setenv("SINAUTH_TEST_BOOL_KEY", v)
		if got := envBool("SINAUTH_TEST_BOOL_KEY", false); !got {
			t.Errorf("envBool(%q) = false, want true", v)
		}
	}
}

func TestEnvBool_FalsyAndFallback(t *testing.T) {
	t.Setenv("SINAUTH_TEST_BOOL_KEY", "false")
	if got := envBool("SINAUTH_TEST_BOOL_KEY", true); got {
		t.Error("envBool(\"false\") = true, want false")
	}

	t.Setenv("SINAUTH_TEST_BOOL_KEY", "")
	if got := envBool("SINAUTH_TEST_BOOL_KEY", true); !got {
		t.Error("envBool(\"\") should return the fallback (true)")
	}
}

func TestEnvDuration_ParsesOrFallsBack(t *testing.T) {
	t.Setenv("SINAUTH_TEST_DURATION_KEY", "30s")
	if got := envDuration("SINAUTH_TEST_DURATION_KEY", time.Minute); got != 30*time.Second {
		t.Errorf("envDuration() = %v, want 30s", got)
	}

	t.Setenv("SINAUTH_TEST_DURATION_KEY", "garbage")
	if got := envDuration("SINAUTH_TEST_DURATION_KEY", time.Minute); got != time.Minute {
		t.Errorf("envDuration() with invalid value = %v, want fallback 1m", got)
	}
}

func TestEnvCSV_SplitsTrimsAndDropsEmpty(t *testing.T) {
	t.Setenv("SINAUTH_TEST_CSV_KEY", "a, b ,, c")
	got := envCSV("SINAUTH_TEST_CSV_KEY")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("envCSV() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("envCSV()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestEnvCSV_EmptyReturnsNil(t *testing.T) {
	t.Setenv("SINAUTH_TEST_CSV_KEY", "")
	if got := envCSV("SINAUTH_TEST_CSV_KEY"); got != nil {
		t.Errorf("envCSV() = %v, want nil", got)
	}
}
