package config_test

import (
	"testing"
	"time"

	"github.com/opensecstack/community/internal/config"
)

// clearCommunityEnv unsets every env var config.Load reads so tests are
// isolated from the developer's shell / CI environment.
func clearCommunityEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"COMMUNITY_HTTP_ADDR", "COMMUNITY_NODE", "COMMUNITY_DEV_MODE",
		"COMMUNITY_DB_URL", "COMMUNITY_DB_MAX_CONNS", "COMMUNITY_JWT_SECRET",
		"COMMUNITY_JWT_ISSUER", "COMMUNITY_TOKEN_TTL", "COMMUNITY_PASSWORD_PEPPER",
		"COMMUNITY_CITADEL_API_URL", "COMMUNITY_CITADEL_KEY_ID", "COMMUNITY_CITADEL_DRY_RUN",
		"COMMUNITY_CITADEL_HMAC_SECRETS", "COMMUNITY_INVITE_ONLY", "COMMUNITY_NATIVE_AUTH",
		"COMMUNITY_ALLOWED_EMAIL_DOMAINS", "MEILISEARCH_URL", "MEILISEARCH_KEY",
		"UPLOAD_DIR", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "GITHUB_CALLBACK_URL",
		"GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI",
		"SINAUTH_URL", "SINAUTH_PUBLIC_URL", "SINAUTH_CLIENT_ID", "SINAUTH_CLIENT_SECRET",
		"SINAUTH_CALLBACK_URL", "SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD",
		"SMTP_FROM", "SITE_URL", "DIGEST_ENABLED", "COMMUNITY_TRUSTED_PROXIES",
		"COMMUNITY_ALLOWED_ORIGINS", "COMMUNITY_USERS",
	}
	for _, k := range keys {
		t.Setenv(k, "")
	}
}

func TestLoad_DevMode_Defaults(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DEV_MODE", "true")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HTTPAddr != ":8090" {
		t.Errorf("expected default HTTPAddr :8090, got %q", cfg.HTTPAddr)
	}
	if cfg.Node != "community-0" {
		t.Errorf("expected default node community-0, got %q", cfg.Node)
	}
	if cfg.DBMaxConns != 16 {
		t.Errorf("expected default DBMaxConns 16, got %d", cfg.DBMaxConns)
	}
	if cfg.TokenTTL != 12*time.Hour {
		t.Errorf("expected default TokenTTL 12h, got %v", cfg.TokenTTL)
	}
	if !cfg.CitadelDryRun {
		t.Error("expected CitadelDryRun to default true")
	}
	if !cfg.NativeAuthEnabled {
		t.Error("expected NativeAuthEnabled to default true")
	}
}

func TestLoad_ProdMode_MissingDBURL_ReturnsError(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_JWT_SECRET", "01234567890123456789012345678901")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error when COMMUNITY_DB_URL is missing outside dev mode")
	}
}

func TestLoad_ProdMode_ShortJWTSecret_ReturnsError(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DB_URL", "postgres://localhost/db")
	t.Setenv("COMMUNITY_JWT_SECRET", "tooshort")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for JWT secret < 32 bytes")
	}
}

func TestLoad_ProdMode_DevPepperSentinel_ReturnsError(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DB_URL", "postgres://localhost/db")
	t.Setenv("COMMUNITY_JWT_SECRET", "01234567890123456789012345678901")
	t.Setenv("COMMUNITY_PASSWORD_PEPPER", "do-not-use-in-prod-pepper")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error when pepper contains dev sentinel outside dev mode")
	}
}

func TestLoad_ProdMode_ValidConfig_Succeeds(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DB_URL", "postgres://localhost/db")
	t.Setenv("COMMUNITY_JWT_SECRET", "01234567890123456789012345678901")
	t.Setenv("COMMUNITY_PASSWORD_PEPPER", "a-real-production-pepper-value")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DBURL != "postgres://localhost/db" {
		t.Errorf("unexpected DBURL: %q", cfg.DBURL)
	}
}

func TestLoad_CommunityUsers_ParsesEntries(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DEV_MODE", "true")
	t.Setenv("COMMUNITY_USERS", "alice:admin:hash1, bob:viewer:hash2")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(cfg.Users))
	}
	if cfg.Users[0].Username != "alice" || cfg.Users[0].Role != "admin" || cfg.Users[0].Hash != "hash1" {
		t.Errorf("unexpected first user: %+v", cfg.Users[0])
	}
	if cfg.Users[1].Username != "bob" || cfg.Users[1].Role != "viewer" || cfg.Users[1].Hash != "hash2" {
		t.Errorf("unexpected second user: %+v", cfg.Users[1])
	}
}

func TestLoad_CommunityUsers_InvalidEntry_ReturnsError(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DEV_MODE", "true")
	t.Setenv("COMMUNITY_USERS", "alice:admin") // missing hash field

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for malformed COMMUNITY_USERS entry")
	}
}

func TestLoad_CommaSeparatedLists(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DEV_MODE", "true")
	t.Setenv("COMMUNITY_CITADEL_HMAC_SECRETS", "secret1,secret2")
	t.Setenv("COMMUNITY_ALLOWED_EMAIL_DOMAINS", "example.com,test.org")
	t.Setenv("COMMUNITY_TRUSTED_PROXIES", "10.0.0.1,10.0.0.2")
	t.Setenv("COMMUNITY_ALLOWED_ORIGINS", "https://sin.to,https://dev.sin.to")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.CitadelHMAC) != 2 || cfg.CitadelHMAC[0] != "secret1" {
		t.Errorf("unexpected CitadelHMAC: %v", cfg.CitadelHMAC)
	}
	if len(cfg.AllowedEmailDomains) != 2 || cfg.AllowedEmailDomains[1] != "test.org" {
		t.Errorf("unexpected AllowedEmailDomains: %v", cfg.AllowedEmailDomains)
	}
	if len(cfg.TrustedProxies) != 2 {
		t.Errorf("unexpected TrustedProxies: %v", cfg.TrustedProxies)
	}
	if len(cfg.AllowedOrigins) != 2 {
		t.Errorf("unexpected AllowedOrigins: %v", cfg.AllowedOrigins)
	}
}

func TestLoad_SinauthPublicURL_DefaultsToSinauthURL(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DEV_MODE", "true")
	t.Setenv("SINAUTH_URL", "http://internal-sinauth:8100")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SinauthPublicURL != "http://internal-sinauth:8100" {
		t.Errorf("expected SinauthPublicURL to default to SinauthURL, got %q", cfg.SinauthPublicURL)
	}
}

func TestLoad_SinauthPublicURL_ExplicitOverride(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DEV_MODE", "true")
	t.Setenv("SINAUTH_URL", "http://internal-sinauth:8100")
	t.Setenv("SINAUTH_PUBLIC_URL", "https://auth.sin.to")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SinauthPublicURL != "https://auth.sin.to" {
		t.Errorf("expected explicit SinauthPublicURL to be preserved, got %q", cfg.SinauthPublicURL)
	}
}

func TestLoad_BoolAndIntEnvParsing(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DEV_MODE", "true")
	t.Setenv("COMMUNITY_DB_MAX_CONNS", "42")
	t.Setenv("SMTP_PORT", "2525")
	t.Setenv("DIGEST_ENABLED", "false")
	t.Setenv("COMMUNITY_INVITE_ONLY", "true")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DBMaxConns != 42 {
		t.Errorf("expected DBMaxConns 42, got %d", cfg.DBMaxConns)
	}
	if cfg.SMTPPort != 2525 {
		t.Errorf("expected SMTPPort 2525, got %d", cfg.SMTPPort)
	}
	if cfg.DigestEnabled {
		t.Error("expected DigestEnabled false")
	}
	if !cfg.InviteOnly {
		t.Error("expected InviteOnly true")
	}
}

func TestLoad_InvalidBoolEnv_FallsBackToDefault(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DEV_MODE", "true")
	t.Setenv("COMMUNITY_INVITE_ONLY", "not-a-bool")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.InviteOnly {
		t.Error("expected invalid bool env to fall back to default (false)")
	}
}

func TestLoad_InvalidDurationEnv_FallsBackToDefault(t *testing.T) {
	clearCommunityEnv(t)
	t.Setenv("COMMUNITY_DEV_MODE", "true")
	t.Setenv("COMMUNITY_TOKEN_TTL", "not-a-duration")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TokenTTL != 12*time.Hour {
		t.Errorf("expected fallback to default 12h TTL, got %v", cfg.TokenTTL)
	}
}
