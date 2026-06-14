package config

import (
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds the complete CITADEL server configuration.
type Config struct {
	Port     int            `mapstructure:"port"`
	LogLevel string         `mapstructure:"log_level"`
	DB       DatabaseConfig `mapstructure:"db"`
	Citadel  CitadelConfig  `mapstructure:"citadel"`
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	URL             string        `mapstructure:"url"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

// CitadelConfig holds CITADEL-specific settings.
type CitadelConfig struct {
	// MasterKey is the Ed25519 private key (hex-encoded) used to sign WORM anchors.
	// Set via CITADEL_MASTER_KEY. If empty, anchoring is skipped.
	MasterKey string `mapstructure:"master_key" json:"-"`
	// AnchorInterval is how many WORM entries between Ed25519 anchor signatures.
	AnchorInterval int `mapstructure:"anchor_interval"`
	// GenesisHash is the published genesis hash for the WORM chain.
	// Default: SHA-256("CITADEL-GENESIS-SIN-v1")
	GenesisHash string `mapstructure:"genesis_hash"`
}

// Load reads configuration from environment variables with defaults applied.
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
		Citadel: CitadelConfig{
			MasterKey:      viper.GetString("citadel.master_key"),
			AnchorInterval: viper.GetInt("citadel.anchor_interval"),
			GenesisHash:    viper.GetString("citadel.genesis_hash"),
		},
	}

	return cfg
}

// WarnIfInsecure logs warnings for unsafe configuration.
func (c *Config) WarnIfInsecure() {
	if c.DB.URL == "" {
		log.Println("WARNING: CITADEL_DB_URL is not set — database connection will fail")
	}
	if c.Citadel.MasterKey == "" {
		log.Println("WARNING: CITADEL_MASTER_KEY is not set — WORM anchor signing is disabled")
	}
}

func setDefaults() {
	viper.SetDefault("port", 8099)
	viper.SetDefault("log_level", "info")

	viper.SetDefault("db.url", "")
	viper.SetDefault("db.max_open_conns", 25)
	viper.SetDefault("db.max_idle_conns", 5)
	viper.SetDefault("db.conn_max_lifetime", 5*time.Minute)

	viper.SetDefault("citadel.master_key", "")
	viper.SetDefault("citadel.anchor_interval", 100)
	// SHA-256("CITADEL-GENESIS-SIN-v1") — precomputed
	viper.SetDefault("citadel.genesis_hash", "b94f6f125c79e3a5ffaa826f584c10d52ada669e6762051b826b55776d05a15")

	viper.SetEnvPrefix("CITADEL")
	// Map nested config keys (e.g. db.url) to env vars (CITADEL_DB_URL).
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
}
