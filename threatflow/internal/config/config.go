package config

import "github.com/spf13/viper"

// Config holds all ThreatFlow configuration.
type Config struct {
	Port     int
	LogLevel string

	DB DatabaseConfig

	Citadel CitadelConfig

	Auth  AuthConfig
	Cache CacheConfig
	Rate  RateLimitConfig
}

// AuthConfig controls JWT issuance + API key bootstrap.
type AuthConfig struct {
	JWTSecret      string   // HS256 signing secret; empty = generate ephemeral
	TTLMinutes     int      // token lifetime in minutes
	BootstrapKeys  []string // comma-separated plaintext keys granted admin role
	SinauthURL     string   // sinauth OIDC issuer URL for RS256 SSO tokens
}

// CacheConfig controls the optional Redis match-cache.
type CacheConfig struct {
	RedisURL   string
	TTLSeconds int
}

// RateLimitConfig controls per-IP token bucket limits.
type RateLimitConfig struct {
	RequestsPerSec float64
	Burst          int
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	URL             string
	MaxOpenConns    int
	MaxIdleConns    int
}

// CitadelConfig holds CITADEL governance integration settings. FailClosed
// toggles whether a MARSHAL check refuses the mutation when CITADEL is
// unreachable (true) or allows it (false). Defaults to fail-open so dev
// environments keep working without the governance service running.
type CitadelConfig struct {
	APIURL     string
	KeyID      string
	KeySecret  string
	ProjectID  string
	FailClosed bool
}

// Load reads configuration from viper with defaults applied.
func Load() *Config {
	setDefaults()
	return &Config{
		Port:     viper.GetInt("port"),
		LogLevel: viper.GetString("log_level"),
		DB: DatabaseConfig{
			URL:          viper.GetString("db.url"),
			MaxOpenConns: viper.GetInt("db.max_open_conns"),
			MaxIdleConns: viper.GetInt("db.max_idle_conns"),
		},
		Citadel: CitadelConfig{
			APIURL:     viper.GetString("citadel.api_url"),
			KeyID:      viper.GetString("citadel.key_id"),
			KeySecret:  viper.GetString("citadel.key_secret"),
			ProjectID:  viper.GetString("citadel.project_id"),
			FailClosed: viper.GetBool("citadel.fail_closed"),
		},
		Auth: AuthConfig{
			JWTSecret:     viper.GetString("auth.jwt_secret"),
			TTLMinutes:    viper.GetInt("auth.ttl_minutes"),
			BootstrapKeys: viper.GetStringSlice("auth.bootstrap_keys"),
			SinauthURL:    viper.GetString("auth.sinauth_url"),
		},
		Cache: CacheConfig{
			RedisURL:   viper.GetString("cache.redis_url"),
			TTLSeconds: viper.GetInt("cache.ttl_seconds"),
		},
		Rate: RateLimitConfig{
			RequestsPerSec: viper.GetFloat64("rate.requests_per_sec"),
			Burst:          viper.GetInt("rate.burst"),
		},
	}
}

func setDefaults() {
	viper.SetDefault("port", 8091)
	viper.SetDefault("log_level", "info")
	viper.SetDefault("db.url", "postgres://threatflow:threatflow@localhost:5432/threatflow?sslmode=disable")
	viper.SetDefault("db.max_open_conns", 25)
	viper.SetDefault("db.max_idle_conns", 5)
	viper.SetDefault("citadel.api_url", "")
	viper.SetDefault("citadel.project_id", "threatflow")
	viper.SetDefault("citadel.fail_closed", false)
	viper.SetDefault("auth.jwt_secret", "")
	viper.SetDefault("auth.ttl_minutes", 60)
	viper.SetDefault("auth.bootstrap_keys", []string{})
	viper.SetDefault("auth.sinauth_url", "http://localhost:8100")
	viper.SetDefault("cache.redis_url", "")
	viper.SetDefault("cache.ttl_seconds", 600)
	viper.SetDefault("rate.requests_per_sec", 50.0)
	viper.SetDefault("rate.burst", 100)
}
