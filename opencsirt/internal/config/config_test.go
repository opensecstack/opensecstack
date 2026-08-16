package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// clearEnv resets every OPENCSIRT_* var this package reads so tests don't
// leak into each other or pick up the host environment.
func clearEnv(t *testing.T) {
	t.Helper()
	vars := []string{
		"OPENCSIRT_HTTP_ADDR", "OPENCSIRT_NODE", "OPENCSIRT_DEV_MODE",
		"OPENCSIRT_DB_URL", "OPENCSIRT_DB_MAX_CONNS", "OPENCSIRT_JWT_SECRET",
		"OPENCSIRT_JWT_ISSUER", "OPENCSIRT_TOKEN_TTL", "OPENCSIRT_USERS",
		"OPENCSIRT_PASSWORD_PEPPER", "OPENCSIRT_SINAUTH_URL",
		"OPENCSIRT_CITADEL_API_URL", "OPENCSIRT_CITADEL_HMAC_SECRETS",
		"OPENCSIRT_CITADEL_KEY_ID", "OPENCSIRT_CITADEL_PROJECT_ID",
		"OPENCSIRT_CITADEL_DRY_RUN", "OPENCSIRT_THREATFLOW_API_URL",
		"OPENCSIRT_THREATFLOW_API_KEY", "OPENCSIRT_THREATFLOW_INTERVAL",
		"OPENCSIRT_NIS2COMPASS_API_URL", "OPENCSIRT_IRFLOW_WEBHOOK_SECRET",
		"OPENCSIRT_IRFLOW_STRICT_SEVERITY", "OPENCSIRT_VERTGUARD_API_URL",
		"OPENCSIRT_VERTGUARD_API_KEY", "OPENCSIRT_TARANIS_API_URL",
		"OPENCSIRT_TARANIS_API_KEY", "OPENCSIRT_TARANIS_HMAC_SECRET",
		"OPENCSIRT_TARANIS_INTERVAL", "OPENCSIRT_ADVISORY_SERVICE_URL",
		"OPENCSIRT_ADVISORY_SERVICE_JWT", "OPENCSIRT_PY_HOST", "OPENCSIRT_PY_PORT",
		"OPENCSIRT_OUTBOX_TICK",
	}
	for _, v := range vars {
		os.Unsetenv(v)
	}
}

func TestFromEnv_Defaults(t *testing.T) {
	clearEnv(t)
	os.Setenv("OPENCSIRT_DEV_MODE", "true")
	defer clearEnv(t)

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.HTTPAddr != ":8088" {
		t.Errorf("HTTPAddr = %q, want :8088", c.HTTPAddr)
	}
	if c.Node != "opencsirt-0" {
		t.Errorf("Node = %q, want opencsirt-0", c.Node)
	}
	if c.DBMaxConns != 16 {
		t.Errorf("DBMaxConns = %d, want 16", c.DBMaxConns)
	}
	if c.TokenTTL != 12*time.Hour {
		t.Errorf("TokenTTL = %v, want 12h", c.TokenTTL)
	}
	if !c.CitadelDryRun {
		t.Errorf("CitadelDryRun default should be true")
	}
	if c.OutboxTickInterval != 10*time.Second {
		t.Errorf("OutboxTickInterval = %v, want 10s", c.OutboxTickInterval)
	}
}

func TestFromEnv_Overrides(t *testing.T) {
	clearEnv(t)
	os.Setenv("OPENCSIRT_DEV_MODE", "true")
	os.Setenv("OPENCSIRT_HTTP_ADDR", ":9999")
	os.Setenv("OPENCSIRT_DB_MAX_CONNS", "42")
	os.Setenv("OPENCSIRT_TOKEN_TTL", "5m")
	os.Setenv("OPENCSIRT_CITADEL_HMAC_SECRETS", "secret-one, secret-two,,")
	defer clearEnv(t)

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.HTTPAddr != ":9999" {
		t.Errorf("HTTPAddr = %q, want :9999", c.HTTPAddr)
	}
	if c.DBMaxConns != 42 {
		t.Errorf("DBMaxConns = %d, want 42", c.DBMaxConns)
	}
	if c.TokenTTL != 5*time.Minute {
		t.Errorf("TokenTTL = %v, want 5m", c.TokenTTL)
	}
	if len(c.CitadelHMACSecrets) != 2 {
		t.Fatalf("CitadelHMACSecrets len = %d, want 2 (blank entries trimmed)", len(c.CitadelHMACSecrets))
	}
	if string(c.CitadelHMACSecrets[0]) != "secret-one" || string(c.CitadelHMACSecrets[1]) != "secret-two" {
		t.Errorf("CitadelHMACSecrets = %v", c.CitadelHMACSecrets)
	}
}

func TestFromEnv_InvalidIntFallsBackToDefault(t *testing.T) {
	clearEnv(t)
	os.Setenv("OPENCSIRT_DEV_MODE", "true")
	os.Setenv("OPENCSIRT_DB_MAX_CONNS", "not-a-number")
	defer clearEnv(t)

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.DBMaxConns != 16 {
		t.Errorf("DBMaxConns = %d, want default 16 when env value is unparsable", c.DBMaxConns)
	}
}

func TestFromEnv_InvalidDurationFallsBackToDefault(t *testing.T) {
	clearEnv(t)
	os.Setenv("OPENCSIRT_DEV_MODE", "true")
	os.Setenv("OPENCSIRT_TOKEN_TTL", "not-a-duration")
	defer clearEnv(t)

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.TokenTTL != 12*time.Hour {
		t.Errorf("TokenTTL = %v, want default 12h when env value is unparsable", c.TokenTTL)
	}
}

func TestEnvBool_Variants(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"1", true}, {"true", true}, {"YES", true}, {"On", true},
		{"0", false}, {"false", false}, {"NO", false}, {"Off", false},
		{"garbage", true}, // unrecognized value falls back to default
	}
	for _, tc := range cases {
		os.Setenv("OPENCSIRT_TEST_BOOL", tc.val)
		got := envBool("OPENCSIRT_TEST_BOOL", true)
		if got != tc.want {
			t.Errorf("envBool(%q) = %v, want %v", tc.val, got, tc.want)
		}
	}
	os.Unsetenv("OPENCSIRT_TEST_BOOL")
	if got := envBool("OPENCSIRT_TEST_BOOL", false); got != false {
		t.Errorf("envBool unset = %v, want default false", got)
	}
}

func TestValidate_DevModeSkipsStrictChecks(t *testing.T) {
	c := &Config{DevMode: true, CitadelDryRun: true}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate in dev mode: %v", err)
	}
}

func TestValidate_ProductionRequiresJWTSecret(t *testing.T) {
	c := &Config{
		DevMode:        false,
		JWTSecret:      []byte("short"),
		PasswordPepper: "real-pepper",
		DBURL:          "postgres://x",
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error for JWT secret < 32 bytes outside dev mode")
	}
}

func TestValidate_ProductionRequiresPepper(t *testing.T) {
	c := &Config{
		DevMode:        false,
		JWTSecret:      []byte("012345678901234567890123456789012"),
		PasswordPepper: "",
		DBURL:          "postgres://x",
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for empty password pepper outside dev mode")
	}

	c.PasswordPepper = "do-not-use-in-prod-default"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for placeholder pepper outside dev mode")
	}
}

func TestValidate_ProductionRequiresDBURL(t *testing.T) {
	c := &Config{
		DevMode:        false,
		JWTSecret:      []byte("012345678901234567890123456789012"),
		PasswordPepper: "real-pepper",
		DBURL:          "",
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for empty DB URL outside dev mode")
	}
}

func TestValidate_CitadelRequiresSecretsWhenNotDryRun(t *testing.T) {
	c := &Config{
		DevMode:            true,
		CitadelDryRun:      false,
		CitadelHMACSecrets: nil,
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when CitadelDryRun=false and no HMAC secrets configured")
	}

	c.CitadelHMACSecrets = [][]byte{[]byte("secret")}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate with secrets configured: %v", err)
	}
}

func TestValidate_ProductionValidConfig(t *testing.T) {
	c := &Config{
		DevMode:        false,
		JWTSecret:      []byte("012345678901234567890123456789012"),
		PasswordPepper: "real-pepper",
		DBURL:          "postgres://x",
		CitadelDryRun:  true,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestParseSecrets(t *testing.T) {
	if got := parseSecrets(""); got != nil {
		t.Errorf("parseSecrets(\"\") = %v, want nil", got)
	}
	got := parseSecrets("a, b ,,c")
	if len(got) != 3 {
		t.Fatalf("parseSecrets len = %d, want 3", len(got))
	}
	if string(got[0]) != "a" || string(got[1]) != "b" || string(got[2]) != "c" {
		t.Errorf("parseSecrets = %v", got)
	}
}

func TestConfig_String_RedactsSecrets(t *testing.T) {
	c := &Config{
		HTTPAddr:  ":8088",
		Node:      "n1",
		JWTSecret: []byte("super-secret-value"),
	}
	s := c.String()
	if strings.Contains(s, "super-secret-value") {
		t.Errorf("String() must not leak the JWT secret value: %q", s)
	}
	if !strings.Contains(s, "JWTSecretSet=true") {
		t.Errorf("String() = %q, want it to report JWTSecretSet=true", s)
	}
}
