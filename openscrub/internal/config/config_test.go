package config

import (
	"errors"
	"os"
	"testing"
	"time"
)

// clearEnv resets every OPENSCRUB_* / SINAUTH_URL var the config package
// reads so tests don't leak state between each other or pick up the host
// environment's own values.
func clearEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"OPENSCRUB_HTTP_ADDR", "OPENSCRUB_DB_URL", "OPENSCRUB_DB_MAX_CONNS",
		"OPENSCRUB_JWT_SECRET", "OPENSCRUB_JWT_ISSUER", "OPENSCRUB_DEV_MODE",
		"OPENSCRUB_THREATFLOW_API_URL", "OPENSCRUB_THREATFLOW_TOKEN",
		"OPENSCRUB_THREATFLOW_INTERVAL", "OPENSCRUB_CITADEL_API_URL",
		"OPENSCRUB_CITADEL_HMAC_SECRET", "OPENSCRUB_CITADEL_HMAC_SECRETS",
		"OPENSCRUB_CITADEL_KEY_ID", "OPENSCRUB_CITADEL_KEY_IDS",
		"OPENSCRUB_CITADEL_DRY_RUN", "OPENSCRUB_NODE", "OPENSCRUB_CITADEL_PROJECT_ID",
		"OPENSCRUB_MITIGATION_MIN_DURATION", "OPENSCRUB_DATAPLANE_TRANSPORT",
		"OPENSCRUB_DATAPLANE_SOCKET", "OPENSCRUB_USERS", "OPENSCRUB_PASSWORD_PEPPER",
		"OPENSCRUB_TOKEN_TTL", "SINAUTH_URL",
	}
	for _, k := range keys {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
}

func TestFromEnvDefaults(t *testing.T) {
	clearEnv(t)
	c := FromEnv()

	if c.HTTPAddr != ":8087" {
		t.Errorf("HTTPAddr default = %q, want :8087", c.HTTPAddr)
	}
	if c.DBURL != "" {
		t.Errorf("DBURL default = %q, want empty", c.DBURL)
	}
	if c.DBMaxConns != 16 {
		t.Errorf("DBMaxConns default = %d, want 16", c.DBMaxConns)
	}
	if c.JWTSecrets != nil {
		t.Errorf("JWTSecrets default = %v, want nil", c.JWTSecrets)
	}
	if c.JWTIssuer != "openscrub" {
		t.Errorf("JWTIssuer default = %q, want openscrub", c.JWTIssuer)
	}
	if c.DevMode {
		t.Error("DevMode default = true, want false")
	}
	if c.ThreatFlowInterval != 15*time.Minute {
		t.Errorf("ThreatFlowInterval default = %v, want 15m", c.ThreatFlowInterval)
	}
	if c.CitadelDryRun {
		t.Error("CitadelDryRun default = true, want false")
	}
	if c.CitadelProjectID != "openscrub" {
		t.Errorf("CitadelProjectID default = %q, want openscrub", c.CitadelProjectID)
	}
	if c.MitigationMinDuration != 5*time.Second {
		t.Errorf("MitigationMinDuration default = %v, want 5s", c.MitigationMinDuration)
	}
	if c.DataplaneTransport != "noop" {
		t.Errorf("DataplaneTransport default = %q, want noop", c.DataplaneTransport)
	}
	if c.DataplaneSocket != "/run/openscrub/dataplane.sock" {
		t.Errorf("DataplaneSocket default = %q", c.DataplaneSocket)
	}
	if c.PasswordPepper != DefaultPasswordPepper {
		t.Errorf("PasswordPepper default = %q, want the build-time default", c.PasswordPepper)
	}
	if c.TokenTTL != time.Hour {
		t.Errorf("TokenTTL default = %v, want 1h", c.TokenTTL)
	}
	if c.SinauthURL != "http://localhost:8100" {
		t.Errorf("SinauthURL default = %q", c.SinauthURL)
	}
	if !c.PasswordPepperIsDefault() {
		t.Error("PasswordPepperIsDefault() = false, want true with unset env")
	}
}

func TestFromEnvOverrides(t *testing.T) {
	clearEnv(t)
	t.Setenv("OPENSCRUB_HTTP_ADDR", ":9999")
	t.Setenv("OPENSCRUB_DB_URL", "postgres://x")
	t.Setenv("OPENSCRUB_DB_MAX_CONNS", "32")
	t.Setenv("OPENSCRUB_JWT_SECRET", "primary, next ,previous")
	t.Setenv("OPENSCRUB_DEV_MODE", "true")
	t.Setenv("OPENSCRUB_CITADEL_DRY_RUN", "1")
	t.Setenv("OPENSCRUB_TOKEN_TTL", "30m")
	t.Setenv("OPENSCRUB_PASSWORD_PEPPER", "a-real-secret")

	c := FromEnv()
	if c.HTTPAddr != ":9999" {
		t.Errorf("HTTPAddr = %q", c.HTTPAddr)
	}
	if c.DBURL != "postgres://x" {
		t.Errorf("DBURL = %q", c.DBURL)
	}
	if c.DBMaxConns != 32 {
		t.Errorf("DBMaxConns = %d", c.DBMaxConns)
	}
	if want := []string{"primary", "next", "previous"}; !equalStrSlices(c.JWTSecrets, want) {
		t.Errorf("JWTSecrets = %v, want %v", c.JWTSecrets, want)
	}
	if !c.DevMode {
		t.Error("DevMode = false, want true")
	}
	if !c.CitadelDryRun {
		t.Error("CitadelDryRun = false, want true")
	}
	if c.TokenTTL != 30*time.Minute {
		t.Errorf("TokenTTL = %v, want 30m", c.TokenTTL)
	}
	if c.PasswordPepperIsDefault() {
		t.Error("PasswordPepperIsDefault() = true, want false with overridden pepper")
	}
}

func TestFromEnvDBMaxConnsInvalidFallsBackToDefault(t *testing.T) {
	clearEnv(t)
	// Negative and non-numeric values must not be accepted.
	t.Setenv("OPENSCRUB_DB_MAX_CONNS", "-5")
	if c := FromEnv(); c.DBMaxConns != 16 {
		t.Errorf("negative DBMaxConns not rejected: got %d", c.DBMaxConns)
	}
	t.Setenv("OPENSCRUB_DB_MAX_CONNS", "notanumber")
	if c := FromEnv(); c.DBMaxConns != 16 {
		t.Errorf("non-numeric DBMaxConns not rejected: got %d", c.DBMaxConns)
	}
}

func TestFromEnvBoolVariants(t *testing.T) {
	clearEnv(t)
	trueVals := []string{"1", "true", "TRUE", "yes", "on"}
	for _, v := range trueVals {
		t.Setenv("OPENSCRUB_DEV_MODE", v)
		if c := FromEnv(); !c.DevMode {
			t.Errorf("DEV_MODE=%q should be true", v)
		}
	}
	falseVals := []string{"0", "false", "FALSE", "no", "off"}
	for _, v := range falseVals {
		t.Setenv("OPENSCRUB_DEV_MODE", v)
		if c := FromEnv(); c.DevMode {
			t.Errorf("DEV_MODE=%q should be false", v)
		}
	}
	// Unrecognised value falls back to the default (false).
	t.Setenv("OPENSCRUB_DEV_MODE", "maybe")
	if c := FromEnv(); c.DevMode {
		t.Error("DEV_MODE=maybe should fall back to default false")
	}
}

func TestFromEnvDurationInvalidFallsBackToDefault(t *testing.T) {
	clearEnv(t)
	t.Setenv("OPENSCRUB_TOKEN_TTL", "not-a-duration")
	if c := FromEnv(); c.TokenTTL != time.Hour {
		t.Errorf("invalid duration not rejected: got %v", c.TokenTTL)
	}
}

func TestValidateRefusesDefaultPepperWithUsersInProdMode(t *testing.T) {
	c := Config{DevMode: false, UsersSpec: "alice:admin:abc", PasswordPepper: DefaultPasswordPepper}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error for default pepper + users in prod mode")
	}
	if !errors.Is(err, ErrInsecureDefaults) {
		t.Errorf("expected error to wrap ErrInsecureDefaults, got %v", err)
	}
}

func TestValidateAllowsDevMode(t *testing.T) {
	c := Config{DevMode: true, UsersSpec: "alice:admin:abc", PasswordPepper: DefaultPasswordPepper}
	if err := c.Validate(); err != nil {
		t.Errorf("dev mode should override the pepper check, got %v", err)
	}
}

func TestValidateAllowsEmptyUsersSpec(t *testing.T) {
	c := Config{DevMode: false, UsersSpec: "", PasswordPepper: DefaultPasswordPepper}
	if err := c.Validate(); err != nil {
		t.Errorf("no login endpoint enabled (empty UsersSpec) should pass, got %v", err)
	}
}

func TestValidateAllowsNonDefaultPepper(t *testing.T) {
	c := Config{DevMode: false, UsersSpec: "alice:admin:abc", PasswordPepper: "a-real-high-entropy-secret"}
	if err := c.Validate(); err != nil {
		t.Errorf("real pepper should pass validation, got %v", err)
	}
}

func equalStrSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
