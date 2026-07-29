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
	// EnforceIdentity, when true, makes Gate 1 (AuthN) and Gate 3 (NDS)
	// REFUSE a Kerkese whose Operator/Verifier sinauth bearer token
	// (ActorToken/VerifierToken) is missing, invalid, or doesn't match the
	// claimed user_id. Defaults to false: irflow's approved actions carry
	// real tokens on both sides, but apiguard's default config
	// (citadel.require_approval=false) and threatflow's single-request
	// governed actions still submit a placeholder Verifier with NO
	// VerifierToken — turning this on unconditionally would REFUSE every one
	// of their governed actions. See
	// citadel/adrs/006-split-enforce-identity-and-signatures.md. Enabling
	// this globally requires apiguard's require_approval (or an equivalent
	// real second-approver flow) to also be on by default — a separate,
	// deliberate product decision, not bundled into this flag.
	EnforceIdentity bool `mapstructure:"enforce_identity"`
	// EnforceSignatures, when true, makes Gate 1 (AuthN) and Gate 3 (NDS)
	// REFUSE a Kerkese whose Operator/Verifier Ed25519 signature is missing,
	// unregistered, or invalid. Defaults to false: no producer has per-user
	// Ed25519 key custody / signing UX yet — see
	// citadel/adrs/004-operator-verifier-ed25519-signatures.md and
	// citadel/adrs/006-split-enforce-identity-and-signatures.md (this flag
	// was split from EnforceIdentity because identity enforcement was ready
	// before signing was). Set via CITADEL_ENFORCE_SIGNATURES=true once at
	// least one producer signs.
	EnforceSignatures bool `mapstructure:"enforce_signatures"`
	// SinauthIssuerURL is the sinauth instance CITADEL verifies Actor/Verifier
	// bearer tokens against (e.g. "https://auth.sin.to"). Required — the
	// server fails to start without it. Set via CITADEL_SINAUTH_ISSUER_URL.
	// See adrs/005-sinauth-identity-bridge.md.
	SinauthIssuerURL string `mapstructure:"sinauth_issuer_url"`
	// PermifyURL is the Permify instance CITADEL's internal/permifysync
	// background sync reads the role→action policy matrix from (the same
	// Permify instance/schema sinauth's internal/authz writes to — there is
	// one ecosystem-wide schema, not two). Empty disables the sync goroutine.
	// Set via CITADEL_PERMIFY_URL.
	PermifyURL string `mapstructure:"permify_url"`
	// EnforcePermifyAuthz, when true, makes Gate 2 (AuthZ) REFUSE a Kerkese
	// whose role/action is explicitly denied by the Permify-derived local
	// snapshot (permify_role_action_snapshot), in addition to the always-on
	// rbacMap check. Defaults to false: a Permify-known deny only WARNs until
	// a deployment explicitly opts in, exactly mirroring EnforceIdentity/
	// EnforceSignatures (ADR-006). The rbacMap check is never gated by this
	// flag — it remains the permanent, unconditional safety net. See
	// citadel/adrs/007-permify-gate2-snapshot.md.
	EnforcePermifyAuthz bool `mapstructure:"enforce_permify_authz"`
	// PermifySyncInterval is how often internal/permifysync refreshes the
	// local snapshot table from Permify. Set via
	// CITADEL_PERMIFY_SYNC_INTERVAL (e.g. "5m").
	PermifySyncInterval time.Duration `mapstructure:"permify_sync_interval"`
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
			MasterKey:         viper.GetString("citadel.master_key"),
			AnchorInterval:    viper.GetInt("citadel.anchor_interval"),
			GenesisHash:       viper.GetString("citadel.genesis_hash"),
			EnforceIdentity:     viper.GetBool("citadel.enforce_identity"),
			EnforceSignatures:   viper.GetBool("citadel.enforce_signatures"),
			SinauthIssuerURL:    viper.GetString("citadel.sinauth_issuer_url"),
			PermifyURL:          viper.GetString("citadel.permify_url"),
			EnforcePermifyAuthz: viper.GetBool("citadel.enforce_permify_authz"),
			PermifySyncInterval: viper.GetDuration("citadel.permify_sync_interval"),
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
	viper.SetDefault("citadel.enforce_identity", false)
	viper.SetDefault("citadel.enforce_signatures", false)
	viper.SetDefault("citadel.sinauth_issuer_url", "")
	viper.SetDefault("citadel.permify_url", "")
	viper.SetDefault("citadel.enforce_permify_authz", false)
	viper.SetDefault("citadel.permify_sync_interval", 5*time.Minute)

	viper.SetEnvPrefix("CITADEL")
	// Map nested config keys (e.g. db.url) to env vars (CITADEL_DB_URL).
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()
}
