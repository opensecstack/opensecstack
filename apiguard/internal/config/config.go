package config

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/viper"
)

// Config holds the complete application configuration.
type Config struct {
	Port      int              `mapstructure:"port"`
	LogLevel  string           `mapstructure:"log_level"`
	DB        DatabaseConfig   `mapstructure:"db"`
	Redis     RedisConfig      `mapstructure:"redis"`
	Scanner   ScannerConfig    `mapstructure:"scanner"`
	Auth      AuthConfig       `mapstructure:"auth"`
	Report    ReportConfig     `mapstructure:"report"`
	Dashboard DashboardConfig  `mapstructure:"dashboard"`
	CORS      CORSConfig       `mapstructure:"cors"`
	RateLimit RateLimitConfig  `mapstructure:"ratelimit"`
	Citadel   CitadelConfig    `mapstructure:"citadel"`
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
	JWTSecret     string        `mapstructure:"jwt_secret" json:"-"`
	TokenExpiry   time.Duration `mapstructure:"token_expiry"`
	EnableAPIKeys bool          `mapstructure:"enable_api_keys"`
	// APIKeys is the list of pre-shared keys accepted by POST /api/v1/auth/token.
	// Set via APIGUARD_AUTH_API_KEYS (comma-separated) or auth.api_keys in config.
	APIKeys []string `mapstructure:"api_keys" json:"-"`
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
}

// CitadelConfig holds CITADEL audit-forwarding settings.
type CitadelConfig struct {
	// APIURL is read from APIGUARD_CITADEL_URL. When empty, forwarding is disabled.
	APIURL string `mapstructure:"api_url" json:"-"`
	// APIKey is read from APIGUARD_CITADEL_API_KEY and sent as a Bearer token.
	APIKey string `mapstructure:"api_key" json:"-"`
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
			JWTSecret:     viper.GetString("auth.jwt_secret"),
			TokenExpiry:   viper.GetDuration("auth.token_expiry"),
			EnableAPIKeys: viper.GetBool("auth.enable_api_keys"),
			APIKeys:       viper.GetStringSlice("auth.api_keys"),
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
			TrustedProxies: viper.GetStringSlice("ratelimit.trusted_proxies"),
		},
		Citadel: CitadelConfig{
			APIURL: viper.GetString("citadel.api_url"),
			APIKey: viper.GetString("citadel.api_key"),
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

	// CITADEL defaults: empty = forwarding disabled.
	// Set APIGUARD_CITADEL_URL=http://citadel-api:8099 to enable.
	viper.SetDefault("citadel.api_url", "")
	viper.SetDefault("citadel.api_key", "")

	viper.SetEnvPrefix("APIGUARD")
	viper.AutomaticEnv()
}
