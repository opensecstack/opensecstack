package config

import (
	"fmt"
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
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	JWTSecret     string        `mapstructure:"jwt_secret" json:"-"`
	TokenExpiry   time.Duration `mapstructure:"token_expiry"`
	EnableAPIKeys bool          `mapstructure:"enable_api_keys"`
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
			Timeout:       viper.GetDuration("scanner.timeout"),
			Concurrency:   viper.GetInt("scanner.concurrency"),
			MaxSpecSize:   viper.GetInt("scanner.max_spec_size"),
			RateLimit:     viper.GetInt("scanner.rate_limit"),
			TLSSkipVerify: viper.GetBool("scanner.tls_skip_verify"),
		},
		Auth: AuthConfig{
			JWTSecret:     viper.GetString("auth.jwt_secret"),
			TokenExpiry:   viper.GetDuration("auth.token_expiry"),
			EnableAPIKeys: viper.GetBool("auth.enable_api_keys"),
		},
		Report: ReportConfig{
			DefaultFormat: viper.GetString("report.default_format"),
			OutputDir:     viper.GetString("report.output_dir"),
		},
		Dashboard: DashboardConfig{
			Enabled:   viper.GetBool("dashboard.enabled"),
			StaticDir: viper.GetString("dashboard.static_dir"),
		},
	}

	return cfg
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
	viper.SetDefault("scanner.max_spec_size", 50) // 50 MB
	viper.SetDefault("scanner.rate_limit", 0)
	viper.SetDefault("scanner.tls_skip_verify", false)

	// Auth defaults.
	viper.SetDefault("auth.token_expiry", 24*time.Hour)
	viper.SetDefault("auth.enable_api_keys", false)

	// Report defaults.
	viper.SetDefault("report.default_format", "table")
	viper.SetDefault("report.output_dir", "./reports")

	// Dashboard defaults.
	viper.SetDefault("dashboard.enabled", true)
	viper.SetDefault("dashboard.static_dir", "./web/dist")
}
