package config

import "github.com/spf13/viper"

// Config holds all ThreatFlow configuration.
type Config struct {
	Port     int
	LogLevel string

	DB DatabaseConfig

	Citadel CitadelConfig
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	URL             string
	MaxOpenConns    int
	MaxIdleConns    int
}

// CitadelConfig holds CITADEL governance integration settings.
type CitadelConfig struct {
	APIURL    string
	KeyID     string
	KeySecret string
	ProjectID string
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
			APIURL:    viper.GetString("citadel.api_url"),
			KeyID:     viper.GetString("citadel.key_id"),
			KeySecret: viper.GetString("citadel.key_secret"),
			ProjectID: viper.GetString("citadel.project_id"),
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
}
