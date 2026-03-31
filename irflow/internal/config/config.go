// Package config provides configuration loading for IRFlow.
package config

import (
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
type NIS2Config struct {
	APIURL string `mapstructure:"api_url"`
	APIKey string `mapstructure:"api_key"`
}

// WebhookConfig holds webhook notification settings.
type WebhookConfig struct {
	Secret      string `mapstructure:"secret"`
	CallbackURL string `mapstructure:"callback_url"`
}

// Load reads configuration from files, environment variables, and defaults.
func Load() (*Config, error) {
	v := viper.New()

	v.SetEnvPrefix("IRFLOW")
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

	// Webhook defaults
	v.SetDefault("webhook.secret", "")
	v.SetDefault("webhook.callback_url", "")

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
