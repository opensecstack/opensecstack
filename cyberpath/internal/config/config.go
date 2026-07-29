// Package config loads CyberPath configuration from env + YAML via Viper.
//
// Mirrors VertGuard's pattern: nested structs per subsystem, viper env
// prefix CYBERPATH_, sensible defaults, optional YAML at
// CYBERPATH_CONFIG_PATH. See docs/configuration.md for the full reference.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// ErrInsecureProdConfig is returned by Config.EnforceProductionGate when
// production environment is detected but the loaded config carries
// dev-only / insecure defaults.
var ErrInsecureProdConfig = errors.New("insecure configuration in production environment")

// Config bundles every runtime knob.
type Config struct {
	Server        ServerConfig        `mapstructure:"server"`
	DB            DBConfig            `mapstructure:"db"`
	Auth          AuthConfig          `mapstructure:"auth"`
	Citadel       CitadelConfig       `mapstructure:"citadel"`
	NIS2          NIS2Config          `mapstructure:"nis2compass"`
	IRFlow        IRFlowConfig        `mapstructure:"irflow"`
	Sandbox       SandboxConfig       `mapstructure:"sandbox"`
	Content       ContentConfig       `mapstructure:"content"`
	I18n          I18nConfig          `mapstructure:"i18n"`
	Cert          CertConfig          `mapstructure:"cert"`
	Observability ObservabilityConfig `mapstructure:"observability"`
}

// ServerConfig — HTTP listener settings.
type ServerConfig struct {
	HTTPAddr        string        `mapstructure:"http_addr"`
	WebPort         int           `mapstructure:"web_port"`
	LogLevel        string        `mapstructure:"log_level"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	RequestIDHeader string        `mapstructure:"request_id_header"`
	DrainGrace      time.Duration `mapstructure:"drain_grace"`
}

// DBConfig — PostgreSQL connection settings.
type DBConfig struct {
	URL            string `mapstructure:"url"`
	Host           string `mapstructure:"host"`
	Port           int    `mapstructure:"port"`
	Name           string `mapstructure:"name"`
	User           string `mapstructure:"user"`
	Password       string `mapstructure:"password"`
	SSLMode        string `mapstructure:"ssl_mode"`
	MaxOpenConns   int    `mapstructure:"max_open_conns"`
	MigrateOnBoot  bool   `mapstructure:"migrate_on_boot"`
}

// EffectiveURL prefers DB.URL when set, otherwise builds from parts.
func (d DBConfig) EffectiveURL() string {
	if d.URL != "" {
		return d.URL
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.Name, d.SSLMode)
}

// AuthConfig — JWT HS256 with 3-slot rotation (primary/next/previous)
// plus the Argon2id password pepper (active + optional previous for
// rotation; see internal/auth/password.go).
type AuthConfig struct {
	Secret         string        `mapstructure:"secret"`
	SecretNext     string        `mapstructure:"secret_next"`
	SecretPrevious string        `mapstructure:"secret_previous"`
	Pepper         string        `mapstructure:"pepper"`
	PepperPrevious string        `mapstructure:"pepper_previous"`
	TokenTTL       time.Duration `mapstructure:"token_ttl"`
	Issuer         string        `mapstructure:"issuer"`
	DevMode        bool          `mapstructure:"dev_mode"`
	// SinauthURL is the issuer URL for the sinauth RS256 SSO provider.
	// When a bearer token carries alg=RS256, it is verified against this
	// endpoint instead of the HS256 secret. Defaults to http://localhost:8100.
	SinauthURL string `mapstructure:"sinauth_url"`
}

// ActiveSecrets returns every non-empty secret in priority order.
func (a AuthConfig) ActiveSecrets() []string {
	out := make([]string, 0, 3)
	if a.Secret != "" {
		out = append(out, a.Secret)
	}
	if a.SecretNext != "" {
		out = append(out, a.SecretNext)
	}
	if a.SecretPrevious != "" {
		out = append(out, a.SecretPrevious)
	}
	return out
}

// CitadelConfig — CITADEL WORM event submission.
type CitadelConfig struct {
	APIURL    string `mapstructure:"api_url"`
	KeyID     string `mapstructure:"key_id"`
	KeySecret string `mapstructure:"key_secret"`
	ProjectID string `mapstructure:"project_id"`
	DryRun    bool   `mapstructure:"dry_run"`
	Enabled   bool   `mapstructure:"enabled"`
}

// NIS2Config — NIS2 Compass connectivity (health-check only; per
// ADR-014 NIS2 Compass pulls coverage/recommend data from CyberPath,
// CyberPath does not push to or authenticate against NIS2 Compass).
type NIS2Config struct {
	APIURL string `mapstructure:"api_url"`
}

// IRFlowConfig — IRFlow webhook integration.
type IRFlowConfig struct {
	APIURL        string `mapstructure:"api_url"`
	WebhookSecret string `mapstructure:"webhook_secret"`
}

// SandboxConfig — lab runtime sandbox.
type SandboxConfig struct {
	Runtime   string `mapstructure:"runtime"` // docker | wasmtime
	CPUQuota  string `mapstructure:"cpu_quota"`
	MemoryMiB int    `mapstructure:"memory_mib"`
	Network   string `mapstructure:"network"`
}

// ContentConfig — track / lesson content path.
type ContentConfig struct {
	Path string `mapstructure:"path"`
}

// I18nConfig — locale handling.
type I18nConfig struct {
	Locales []string `mapstructure:"locales"`
	Default string   `mapstructure:"default"`
}

// CertConfig — certification PDF signing.
type CertConfig struct {
	SigningKeyPath string `mapstructure:"signing_key_path"`
	IssuerName     string `mapstructure:"issuer_name"`
	// SigningKeyPEM is the PEM-encoded Ed25519 private key used to sign
	// issued certifications. Accepts PKCS#8 ("PRIVATE KEY") or OpenSSH
	// ("OPENSSH PRIVATE KEY") format. When empty, the cert signer generates
	// an ephemeral key on startup — suitable for dev/test only.
	// Env var: CYBERPATH_CERT_SIGNING_KEY_PEM
	SigningKeyPEM string `mapstructure:"signing_key_pem"`
}

// ObservabilityConfig — metrics + tracing.
type ObservabilityConfig struct {
	MetricsEnabled bool   `mapstructure:"metrics_enabled"`
	TracingEnabled bool   `mapstructure:"tracing_enabled"`
	OTLPEndpoint   string `mapstructure:"otlp_endpoint"`
}

// Load reads configuration from env (prefix CYBERPATH_) plus optional YAML.
func Load() (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix("CYBERPATH")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(envReplacer())

	setDefaults(v)

	if path := v.GetString("config_path"); path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cfg, nil
}

// IsProductionEnv reports whether the process appears to run in production.
func IsProductionEnv() bool {
	for _, key := range []string{"CYBERPATH_ENV", "GO_ENV"} {
		if v, ok := os.LookupEnv(key); ok {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "production", "prod":
				return true
			default:
				return false
			}
		}
	}
	return false
}

// Validate returns errors for missing required fields in production mode.
func (c *Config) Validate() error {
	if !IsProductionEnv() {
		return nil
	}
	var reasons []string
	if c.Auth.DevMode {
		reasons = append(reasons, "auth.dev_mode=true — JWT verification bypassed in prod")
	}
	if c.Auth.Secret == "" {
		reasons = append(reasons, "auth.secret is empty — JWT signing key missing")
	}
	if strings.EqualFold(c.DB.SSLMode, "disable") && c.DB.URL == "" {
		reasons = append(reasons, "db.ssl_mode=disable — Postgres traffic would be cleartext")
	}
	if c.DB.Password == "" && c.DB.URL == "" {
		reasons = append(reasons, "db.password and db.url both empty — cannot connect")
	}
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInsecureProdConfig, strings.Join(reasons, "; "))
}

// WarnIfInsecure returns startup warnings for non-production configs.
func (c *Config) WarnIfInsecure() []string {
	var warns []string
	if c.Auth.Secret == "" {
		warns = append(warns, "CYBERPATH_AUTH_SECRET empty — dev mode; never run this way in production")
	}
	if c.Auth.DevMode {
		warns = append(warns, "CYBERPATH_AUTH_DEV_MODE=true — authentication bypassed")
	}
	if c.DB.SSLMode == "disable" {
		warns = append(warns, "CYBERPATH_DB_SSL_MODE=disable — use 'require' in production")
	}
	if c.Citadel.APIURL == "" {
		warns = append(warns, "CYBERPATH_CITADEL_API_URL empty — completion events will NOT be WORM-logged")
	}
	if c.Cert.SigningKeyPEM == "" {
		warns = append(warns, "CYBERPATH_CERT_SIGNING_KEY_PEM empty — ephemeral Ed25519 key in use; certifications will not survive restart")
	}
	return warns
}
