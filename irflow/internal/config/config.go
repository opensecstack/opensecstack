// Package config provides configuration loading for IRFlow.
package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the IRFlow service.
type Config struct {
	Server  ServerConfig
	DB      DBConfig
	Citadel CitadelConfig
	NIS2    NIS2Config
	Webhook WebhookConfig
	Auth    AuthConfig
}

// AuthConfig holds JWT signing and enforcement settings.
//
// DevMode disables the auth middleware entirely — useful for local
// development and integration tests but must never be enabled in production.
// When Secret is empty, DevMode defaults to true with a warning at startup.
//
// Pepper is the server-side secret fed into Argon2id when hashing API keys
// or other long-lived credentials. Must be >= 16 bytes. Leave empty to
// disable password hashing helpers at startup (first call to
// auth.NewHasher will surface a typed error).
type AuthConfig struct {
	Secret   string        `mapstructure:"secret"`
	TokenTTL time.Duration `mapstructure:"token_ttl"`
	Issuer   string        `mapstructure:"issuer"`
	DevMode  bool          `mapstructure:"dev_mode"`
	Pepper   string        `mapstructure:"pepper"`
	// SinauthURL is the issuer URL for the sinauth RS256 SSO provider.
	// When a bearer token carries alg=RS256, it is verified against this
	// endpoint instead of the HS256 secret. Defaults to http://localhost:8100.
	SinauthURL string `mapstructure:"sinauth_url"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// DBConfig holds database connection settings.
type DBConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Name     string `mapstructure:"name"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

// CitadelConfig holds CITADEL governance integration settings.
type CitadelConfig struct {
	APIURL    string `mapstructure:"api_url"`
	KeyID     string `mapstructure:"key_id"`
	KeySecret string `mapstructure:"key_secret"`
	ProjectID string `mapstructure:"project_id"`
	DryRun    bool   `mapstructure:"dry_run"`
}

// NIS2Config holds NIS2 Compass integration settings.
//
// AssessmentID designates which NIS2 Compass assessment IRFlow writes to when
// recording incidents. MeasureRef is the Article 21(2) letter to update (by
// convention "b" for Incident Handling). Both must be present for NIS2
// notifications to fire; when either is empty, incident creation still
// succeeds but the notification step is skipped with a warning log.
type NIS2Config struct {
	APIURL       string `mapstructure:"api_url"`
	APIKey       string `mapstructure:"api_key"`
	AssessmentID string `mapstructure:"assessment_id"`
	MeasureRef   string `mapstructure:"measure_ref"`
}

// WebhookConfig holds webhook notification and ingress settings.
//
// Secret is retained as a shared fallback used when a per-source secret is
// empty. Per-source secrets take precedence and are the recommended
// configuration for production (each sender gets its own rotatable key).
type WebhookConfig struct {
	Secret             string        `mapstructure:"secret"`
	APIGuardSecret     string        `mapstructure:"apiguard_secret"`
	CITADELSecret      string        `mapstructure:"citadel_secret"`
	ThreatFlowSecret   string        `mapstructure:"threatflow_secret"`
	CyberPathSecret    string        `mapstructure:"cyberpath_secret"`
	CallbackURL        string        `mapstructure:"callback_url"`
	MaxBodySize        int64         `mapstructure:"max_body_size"`
	ClockSkewTolerance time.Duration `mapstructure:"clock_skew_tolerance"`
}

// ResolvedSecret returns the per-source secret if set, otherwise falls back
// to the shared Secret. An empty return value means no secret is configured
// and the corresponding webhook endpoint must reject all requests.
func (w WebhookConfig) ResolvedSecret(source string) string {
	switch source {
	case "apiguard":
		if w.APIGuardSecret != "" {
			return w.APIGuardSecret
		}
	case "citadel":
		if w.CITADELSecret != "" {
			return w.CITADELSecret
		}
	case "threatflow":
		if w.ThreatFlowSecret != "" {
			return w.ThreatFlowSecret
		}
	case "cyberpath":
		if w.CyberPathSecret != "" {
			return w.CyberPathSecret
		}
	}
	return w.Secret
}

// Load reads configuration from files, environment variables, and defaults.
func Load() (*Config, error) {
	v := viper.New()

	v.SetEnvPrefix("IRFLOW")
	// Map nested config keys (e.g. db.host) to env vars (IRFLOW_DB_HOST).
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8083)
	v.SetDefault("server.read_timeout", 15*time.Second)
	v.SetDefault("server.write_timeout", 15*time.Second)

	// DB defaults
	v.SetDefault("db.host", "localhost")
	v.SetDefault("db.port", 5432)
	v.SetDefault("db.name", "irflow")
	v.SetDefault("db.user", "irflow")
	v.SetDefault("db.password", "")
	v.SetDefault("db.ssl_mode", "disable")

	// Citadel defaults
	v.SetDefault("citadel.api_url", "http://localhost:8082")
	v.SetDefault("citadel.key_id", "")
	v.SetDefault("citadel.key_secret", "")
	v.SetDefault("citadel.project_id", "")
	v.SetDefault("citadel.dry_run", true)

	// NIS2 defaults
	v.SetDefault("nis2.api_url", "http://localhost:8081")
	v.SetDefault("nis2.api_key", "")
	v.SetDefault("nis2.assessment_id", "")
	v.SetDefault("nis2.measure_ref", "b") // Article 21(2)(b) — Incident Handling

	// Auth defaults
	v.SetDefault("auth.secret", "")
	v.SetDefault("auth.token_ttl", 8*time.Hour)
	v.SetDefault("auth.issuer", "irflow")
	v.SetDefault("auth.dev_mode", false)
	v.SetDefault("auth.pepper", "")
	v.SetDefault("auth.sinauth_url", "http://localhost:8100")

	// Webhook defaults
	v.SetDefault("webhook.secret", "")
	v.SetDefault("webhook.apiguard_secret", "")
	v.SetDefault("webhook.citadel_secret", "")
	v.SetDefault("webhook.threatflow_secret", "")
	v.SetDefault("webhook.cyberpath_secret", "")
	v.SetDefault("webhook.callback_url", "")
	v.SetDefault("webhook.max_body_size", 1<<20) // 1 MiB
	v.SetDefault("webhook.clock_skew_tolerance", 5*time.Minute)

	// Attempt to read config file (optional)
	v.SetConfigName("irflow")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/irflow")
	_ = v.ReadInConfig() // config file is optional

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
