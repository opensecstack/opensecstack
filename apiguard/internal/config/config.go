package config

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds the complete application configuration.
type Config struct {
	Port      int             `mapstructure:"port"`
	LogLevel  string          `mapstructure:"log_level"`
	DB        DatabaseConfig  `mapstructure:"db"`
	Redis     RedisConfig     `mapstructure:"redis"`
	Scanner   ScannerConfig   `mapstructure:"scanner"`
	Auth      AuthConfig      `mapstructure:"auth"`
	Report    ReportConfig    `mapstructure:"report"`
	Dashboard DashboardConfig `mapstructure:"dashboard"`
	CORS      CORSConfig      `mapstructure:"cors"`
	RateLimit RateLimitConfig `mapstructure:"ratelimit"`
	Citadel   CitadelConfig   `mapstructure:"citadel"`
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	URL             string        `mapstructure:"url"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	URL      string `mapstructure:"url"`
	Password string `mapstructure:"password" json:"-"`
	DB       int    `mapstructure:"db"`
}

// ScannerConfig holds scanner-specific settings.
type ScannerConfig struct {
	Timeout       time.Duration `mapstructure:"timeout"`
	Concurrency   int           `mapstructure:"concurrency"`
	MaxSpecSize   int           `mapstructure:"max_spec_size"` // MB
	RateLimit     int           `mapstructure:"rate_limit"`
	TLSSkipVerify bool          `mapstructure:"tls_skip_verify"`
	// CustomRulesDir is the path to a directory of *.yaml custom rule files.
	// Set via the APIGUARD_CUSTOM_RULES_DIR environment variable or
	// scanner.custom_rules_dir in apiguard.yaml. Empty means no custom rules.
	CustomRulesDir string `mapstructure:"custom_rules_dir"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	JWTSecret string `mapstructure:"jwt_secret" json:"-"`
	// SinauthURL is the base URL of the sinauth OIDC issuer used for RS256 SSO
	// token verification. Set via APIGUARD_AUTH_SINAUTH_URL or auth.sinauth_url
	// in config. When non-empty, Bearer tokens with alg=RS256 are verified via
	// the sinauth SDK; HS256 tokens continue to use the existing HMAC path.
	// Default: "http://localhost:8100"
	SinauthURL string `mapstructure:"sinauth_url"`
	// PreviousJWTSecret supports zero-downtime JWT secret rotation (legacy two-slot
	// mechanism). Prefer JWTSecrets for multi-key rotation. Kept for backward compat.
	// Set via APIGUARD_AUTH_PREVIOUS_JWT_SECRET or auth.previous_jwt_secret in config.
	PreviousJWTSecret string `mapstructure:"previous_jwt_secret" json:"-"`
	// JWTSecrets is the multi-secret rotation list. Index 0 is the active signing
	// key; subsequent entries are grace-period verification-only keys (up to 3 total).
	// Set via APIGUARD_AUTH_JWT_SECRETS (comma-separated) or auth.jwt_secrets in config.
	// When JWTSecrets is non-empty it takes precedence over JWTSecret/PreviousJWTSecret.
	// When only JWTSecret is set it is treated as a single-entry list for compat.
	JWTSecrets    []string      `mapstructure:"jwt_secrets" json:"-"`
	TokenExpiry   time.Duration `mapstructure:"token_expiry"`
	EnableAPIKeys bool          `mapstructure:"enable_api_keys"`
	// APIKeys is the list of pre-shared keys accepted by POST /api/v1/auth/token.
	// Set via APIGUARD_AUTH_API_KEYS (comma-separated) or auth.api_keys in config.
	APIKeys []string `mapstructure:"api_keys" json:"-"`
}

// EffectiveJWTSecrets returns the canonical ordered list of JWT secrets to use
// for the SecretProvider. Resolution order (first non-empty wins):
//  1. JWTSecrets (multi-secret list from APIGUARD_AUTH_JWT_SECRETS or config)
//  2. JWTSecret + PreviousJWTSecret (legacy two-slot config — backward compat)
//
// The returned slice has at most 3 entries; empty strings are excluded.
func (a AuthConfig) EffectiveJWTSecrets() []string {
	if len(a.JWTSecrets) > 0 {
		return a.JWTSecrets
	}
	var out []string
	if a.JWTSecret != "" {
		out = append(out, a.JWTSecret)
	}
	if a.PreviousJWTSecret != "" {
		out = append(out, a.PreviousJWTSecret)
	}
	return out
}

// String returns a safe representation of AuthConfig with secrets redacted.
func (a AuthConfig) String() string {
	secret := "[REDACTED]"
	if a.JWTSecret == "" {
		secret = "[NOT SET]"
	}
	return fmt.Sprintf("AuthConfig{JWTSecret: %s}", secret)
}

// ReportConfig holds report generation settings.
type ReportConfig struct {
	DefaultFormat string `mapstructure:"default_format"`
	OutputDir     string `mapstructure:"output_dir"`
}

// DashboardConfig holds web dashboard settings.
type DashboardConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	StaticDir string `mapstructure:"static_dir"`
}

// CORSConfig holds Cross-Origin Resource Sharing settings.
type CORSConfig struct {
	// Origins is the list of allowed origins for CORS requests.
	// Set via APIGUARD_CORS_ORIGINS (comma-separated).
	// An empty list (the default) denies all cross-origin requests — explicit
	// configuration is required. Use "*" to permit all origins (wildcard mode,
	// suitable for development only).
	Origins []string `mapstructure:"origins"`
}

// RateLimitConfig holds rate-limiter settings.
type RateLimitConfig struct {
	// TrustedProxies is the list of upstream proxy IPs (or CIDR blocks) whose
	// X-Forwarded-For header the rate limiter should trust. When empty,
	// X-Forwarded-For is ignored and RemoteAddr is always used.
	// Set via APIGUARD_RATELIMIT_TRUSTED_PROXIES (comma-separated).
	TrustedProxies []string `mapstructure:"trusted_proxies"`

	// TrustedProxyDepth controls how many proxy hops to skip when reading the
	// real client IP from X-Forwarded-For. A value of 1 (the default) means
	// trust the leftmost IP in XFF, which is correct for a single-proxy setup.
	// Set to 2 when two trusted proxies sit in front of the server (e.g. an
	// external LB in front of an nginx ingress) — the server will then use the
	// second-from-right IP in XFF, skipping the innermost proxy hop.
	// Values less than 1 are treated as 1.
	// Set via APIGUARD_RATELIMIT_TRUSTED_PROXY_DEPTH.
	TrustedProxyDepth int `mapstructure:"trusted_proxy_depth"`
}

// CitadelConfig holds CITADEL governance integration settings.
type CitadelConfig struct {
	// APIURL is read from APIGUARD_CITADEL_URL. When empty, all CITADEL calls are no-ops.
	APIURL string `mapstructure:"api_url" json:"-"`
	// KeyID is the HMAC connector key identifier (X-CITADEL-KEY header).
	KeyID string `mapstructure:"key_id" json:"-"`
	// KeySecret is the HMAC-SHA256 signing secret (never logged or serialised).
	KeySecret string `mapstructure:"key_secret" json:"-"`
	// ProjectID identifies this apiguard instance as a CITADEL project.
	// Used as the project_id in Kerkese payloads and WORM events.
	ProjectID string `mapstructure:"project_id"`
	// DryRun controls whether MARSHAL evaluate calls use dry_run=true.
	// When true, CITADEL logs the decision but never blocks scans.
	// Default: true (safe for initial rollout).
	DryRun bool `mapstructure:"dry_run"`
	// WebhookSecret is the HMAC-SHA256 shared secret used to verify inbound
	// webhook events from CITADEL. Set via APIGUARD_CITADEL_WEBHOOK_SECRET.
	// When empty, the webhook endpoint rejects all requests with 401.
	WebhookSecret string `mapstructure:"webhook_secret" json:"-"`
	// RequireApproval, when true, requires a genuine second authenticated user
	// (a real, distinct sinauth identity — never a placeholder) to approve a
	// scan via POST /api/v1/scans/{id}/approve before it launches. This
	// replaces the fixed "apiguard-system-verifier" placeholder with a real
	// two-person Separation-of-Duties flow feeding CITADEL Gate 3 (NDS) with
	// two distinct, independently-authenticated identities.
	//
	// Default: false — scans launch immediately after CITADEL evaluation with
	// the placeholder Verifier, exactly like today, until an operator opts in.
	// This mirrors citadel.enforce_signatures' soft-rollout philosophy: ship
	// the capability, but don't change default behavior (and risk breaking
	// existing API consumers/tests) until the deployer is ready.
	// Set via APIGUARD_CITADEL_REQUIRE_APPROVAL or citadel.require_approval.
	RequireApproval bool `mapstructure:"require_approval"`
}

// Load reads configuration from viper with defaults applied.
func Load() *Config {
	setDefaults()

	cfg := &Config{
		Port:     viper.GetInt("port"),
		LogLevel: viper.GetString("log_level"),
		DB: DatabaseConfig{
			URL:             viper.GetString("db.url"),
			MaxOpenConns:    viper.GetInt("db.max_open_conns"),
			MaxIdleConns:    viper.GetInt("db.max_idle_conns"),
			ConnMaxLifetime: viper.GetDuration("db.conn_max_lifetime"),
		},
		Redis: RedisConfig{
			URL:      viper.GetString("redis.url"),
			Password: viper.GetString("redis.password"),
			DB:       viper.GetInt("redis.db"),
		},
		Scanner: ScannerConfig{
			Timeout:        viper.GetDuration("scanner.timeout"),
			Concurrency:    viper.GetInt("scanner.concurrency"),
			MaxSpecSize:    viper.GetInt("scanner.max_spec_size"),
			RateLimit:      viper.GetInt("scanner.rate_limit"),
			TLSSkipVerify:  viper.GetBool("scanner.tls_skip_verify"),
			CustomRulesDir: viper.GetString("scanner.custom_rules_dir"),
		},
		Auth: AuthConfig{
			JWTSecret:         viper.GetString("auth.jwt_secret"),
			PreviousJWTSecret: viper.GetString("auth.previous_jwt_secret"),
			JWTSecrets:        viper.GetStringSlice("auth.jwt_secrets"),
			TokenExpiry:       viper.GetDuration("auth.token_expiry"),
			EnableAPIKeys:     viper.GetBool("auth.enable_api_keys"),
			APIKeys:           viper.GetStringSlice("auth.api_keys"),
			SinauthURL:        viper.GetString("auth.sinauth_url"),
		},
		Report: ReportConfig{
			DefaultFormat: viper.GetString("report.default_format"),
			OutputDir:     viper.GetString("report.output_dir"),
		},
		Dashboard: DashboardConfig{
			Enabled:   viper.GetBool("dashboard.enabled"),
			StaticDir: viper.GetString("dashboard.static_dir"),
		},
		CORS: CORSConfig{
			Origins: viper.GetStringSlice("cors.origins"),
		},
		RateLimit: RateLimitConfig{
			TrustedProxies:    viper.GetStringSlice("ratelimit.trusted_proxies"),
			TrustedProxyDepth: viper.GetInt("ratelimit.trusted_proxy_depth"),
		},
		Citadel: CitadelConfig{
			APIURL:          viper.GetString("citadel.api_url"),
			KeyID:           viper.GetString("citadel.key_id"),
			KeySecret:       viper.GetString("citadel.key_secret"),
			ProjectID:       viper.GetString("citadel.project_id"),
			DryRun:          viper.GetBool("citadel.dry_run"),
			WebhookSecret:   viper.GetString("citadel.webhook_secret"),
			RequireApproval: viper.GetBool("citadel.require_approval"),
		},
	}

	return cfg
}

// WarnIfInsecure logs a prominent warning for any configuration options that
// are unsafe for production use. It should be called once at startup, after
// Load() returns.
func (c *Config) WarnIfInsecure() {
	if c.Scanner.TLSSkipVerify {
		log.Println("WARNING: TLS certificate verification is disabled (TLS_SKIP_VERIFY=true) — do not use in production")
	}
	if c.Auth.JWTSecret == "" {
		log.Println("WARNING: JWT secret is not configured — all authenticated requests will fail with 503")
	}
}

func setDefaults() {
	viper.SetDefault("port", 8080)
	viper.SetDefault("log_level", "info")

	// Database defaults.
	viper.SetDefault("db.url", "")
	viper.SetDefault("db.max_open_conns", 25)
	viper.SetDefault("db.max_idle_conns", 5)
	viper.SetDefault("db.conn_max_lifetime", 5*time.Minute)

	// Redis defaults.
	viper.SetDefault("redis.url", "redis://localhost:6379")
	viper.SetDefault("redis.db", 0)

	// Scanner defaults.
	viper.SetDefault("scanner.timeout", 5*time.Minute)
	viper.SetDefault("scanner.concurrency", 10)
	viper.SetDefault("scanner.max_spec_size", 10) // 10 MB
	viper.SetDefault("scanner.rate_limit", 0)
	viper.SetDefault("scanner.tls_skip_verify", false)
	viper.SetDefault("scanner.custom_rules_dir", "") // empty = no custom rules loaded

	// Auth defaults.
	viper.SetDefault("auth.token_expiry", 24*time.Hour)
	viper.SetDefault("auth.enable_api_keys", false)
	// auth.jwt_secrets: comma-separated multi-secret list (APIGUARD_AUTH_JWT_SECRETS).
	// When empty, the server falls back to auth.jwt_secret / auth.previous_jwt_secret.
	viper.SetDefault("auth.jwt_secrets", []string{})
	// auth.sinauth_url: sinauth OIDC issuer for RS256 SSO token verification.
	// Set APIGUARD_AUTH_SINAUTH_URL to override. Empty disables RS256 path.
	viper.SetDefault("auth.sinauth_url", "http://localhost:8100")

	// Report defaults.
	viper.SetDefault("report.default_format", "json")
	viper.SetDefault("report.output_dir", "./reports")

	// Dashboard defaults.
	viper.SetDefault("dashboard.enabled", true)
	viper.SetDefault("dashboard.static_dir", "./web/dist")

	// CORS defaults: empty list = deny all cross-origin requests (safe default).
	// Set APIGUARD_CORS_ORIGINS=https://app.example.com,https://other.example.com to allow
	// specific origins, or APIGUARD_CORS_ORIGINS=* to permit all origins (development only).
	viper.SetDefault("cors.origins", []string{})

	// Rate-limiter defaults: no trusted proxies — always use RemoteAddr.
	// Set APIGUARD_RATELIMIT_TRUSTED_PROXIES=10.0.0.1,10.0.0.2 to trust specific upstream proxies.
	viper.SetDefault("ratelimit.trusted_proxies", []string{})
	// TrustedProxyDepth=1 means use the leftmost XFF entry (single-proxy setup).
	// Increase when multiple trusted proxies sit in front of the server.
	viper.SetDefault("ratelimit.trusted_proxy_depth", 1)

	// CITADEL defaults: empty = forwarding disabled.
	// Set APIGUARD_CITADEL_URL=http://citadel-api:8099 to enable.
	viper.SetDefault("citadel.api_url", "")
	viper.SetDefault("citadel.key_id", "")
	viper.SetDefault("citadel.key_secret", "")
	viper.SetDefault("citadel.project_id", "apiguard")
	viper.SetDefault("citadel.webhook_secret", "")
	// dry_run=true by default — CITADEL logs decisions without blocking scans.
	// Set APIGUARD_CITADEL_DRY_RUN=false to enable full governance enforcement.
	viper.SetDefault("citadel.dry_run", true)
	// require_approval=false by default — preserves today's immediate-launch
	// behavior. Set APIGUARD_CITADEL_REQUIRE_APPROVAL=true to require a real,
	// distinct second user to approve every scan before it runs.
	viper.SetDefault("citadel.require_approval", false)

	viper.SetEnvPrefix("APIGUARD")
	// Map nested config keys (e.g. db.url) to env vars (APIGUARD_DB_URL).
	// Without this, AutomaticEnv cannot resolve dotted keys from the environment.
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
}
