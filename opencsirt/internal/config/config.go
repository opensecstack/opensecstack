// Package config loads OpenCSIRT runtime configuration from the
// environment. Names are stable (operator-facing); see docs/configuration.md.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Server
	HTTPAddr string
	Node     string
	DevMode  bool

	// DB
	DBURL      string
	DBMaxConns int

	// Auth
	JWTSecret      []byte
	JWTIssuer      string
	TokenTTL       time.Duration
	Users          string // user:role:sha256hex,...
	PasswordPepper string
	// SinauthURL is the sinauth issuer URL for RS256 SSO token verification.
	// When a bearer token carries alg=RS256, it is verified against this endpoint.
	// Env var: OPENCSIRT_SINAUTH_URL (default http://localhost:8100).
	SinauthURL string

	// CITADEL
	CitadelAPIURL      string
	CitadelHMACSecrets [][]byte
	CitadelKeyID       string
	// CitadelProjectID is forwarded as project_id on every WORM emit and on
	// every Kerkese governance evaluation submitted to MARSHAL.
	CitadelProjectID string
	CitadelDryRun    bool

	// ThreatFlow
	ThreatFlowAPIURL   string
	ThreatFlowAPIKey   string
	ThreatFlowInterval time.Duration

	// NIS2 Compass
	NIS2CompassAPIURL string

	// IRFlow webhook
	IRFlowWebhookSecret  string
	IRFlowStrictSeverity bool // reject rather than coerce unknown severity values

	// VertGuard
	VertGuardAPIURL string
	VertGuardAPIKey string

	// TARANIS-NG OSINT ingestion
	TaranisAPIURL     string
	TaranisAPIKey     string
	TaranisHMACSecret []byte
	TaranisInterval   time.Duration

	// Python advisory subsystem
	AdvisoryServiceURL string
	AdvisoryServiceJWT string
	AdvisoryPyHost     string
	AdvisoryPyPort     string

	// Mitigation/incident timing
	OutboxTickInterval time.Duration
}

func FromEnv() (*Config, error) {
	c := &Config{
		HTTPAddr:             env("OPENCSIRT_HTTP_ADDR", ":8088"),
		Node:                 env("OPENCSIRT_NODE", "opencsirt-0"),
		DevMode:              envBool("OPENCSIRT_DEV_MODE", false),
		DBURL:                env("OPENCSIRT_DB_URL", ""),
		DBMaxConns:           envInt("OPENCSIRT_DB_MAX_CONNS", 16),
		JWTSecret:            []byte(env("OPENCSIRT_JWT_SECRET", "")),
		JWTIssuer:            env("OPENCSIRT_JWT_ISSUER", "opencsirt"),
		TokenTTL:             envDuration("OPENCSIRT_TOKEN_TTL", 12*time.Hour),
		Users:                env("OPENCSIRT_USERS", ""),
		PasswordPepper:       env("OPENCSIRT_PASSWORD_PEPPER", ""),
		SinauthURL:           env("OPENCSIRT_SINAUTH_URL", "http://localhost:8100"),
		CitadelAPIURL:        env("OPENCSIRT_CITADEL_API_URL", ""),
		CitadelHMACSecrets:   parseSecrets(env("OPENCSIRT_CITADEL_HMAC_SECRETS", "")),
		CitadelKeyID:         env("OPENCSIRT_CITADEL_KEY_ID", "opencsirt-1"),
		CitadelProjectID:     env("OPENCSIRT_CITADEL_PROJECT_ID", "opencsirt"),
		CitadelDryRun:        envBool("OPENCSIRT_CITADEL_DRY_RUN", true),
		ThreatFlowAPIURL:     env("OPENCSIRT_THREATFLOW_API_URL", ""),
		ThreatFlowAPIKey:     env("OPENCSIRT_THREATFLOW_API_KEY", ""),
		ThreatFlowInterval:   envDuration("OPENCSIRT_THREATFLOW_INTERVAL", 15*time.Minute),
		NIS2CompassAPIURL:    env("OPENCSIRT_NIS2COMPASS_API_URL", ""),
		IRFlowWebhookSecret:  env("OPENCSIRT_IRFLOW_WEBHOOK_SECRET", ""),
		IRFlowStrictSeverity: envBool("OPENCSIRT_IRFLOW_STRICT_SEVERITY", false),
		VertGuardAPIURL:      env("OPENCSIRT_VERTGUARD_API_URL", ""),
		VertGuardAPIKey:      env("OPENCSIRT_VERTGUARD_API_KEY", ""),
		TaranisAPIURL:        env("OPENCSIRT_TARANIS_API_URL", ""),
		TaranisAPIKey:        env("OPENCSIRT_TARANIS_API_KEY", ""),
		TaranisHMACSecret:    []byte(env("OPENCSIRT_TARANIS_HMAC_SECRET", "")),
		TaranisInterval:      envDuration("OPENCSIRT_TARANIS_INTERVAL", 15*time.Minute),
		AdvisoryServiceURL:   env("OPENCSIRT_ADVISORY_SERVICE_URL", ""),
		AdvisoryServiceJWT:   env("OPENCSIRT_ADVISORY_SERVICE_JWT", ""),
		AdvisoryPyHost:       env("OPENCSIRT_PY_HOST", "localhost"),
		AdvisoryPyPort:       env("OPENCSIRT_PY_PORT", "8089"),
		OutboxTickInterval:   envDuration("OPENCSIRT_OUTBOX_TICK", 10*time.Second),
	}
	return c, c.Validate()
}

func (c *Config) Validate() error {
	if !c.DevMode {
		if len(c.JWTSecret) < 32 {
			return errors.New("OPENCSIRT_JWT_SECRET must be ≥32 bytes outside dev mode")
		}
		if c.PasswordPepper == "" || strings.Contains(c.PasswordPepper, "do-not-use-in-prod") {
			return errors.New("OPENCSIRT_PASSWORD_PEPPER must be set to a real value outside dev mode")
		}
		if c.DBURL == "" {
			return errors.New("OPENCSIRT_DB_URL required outside dev mode")
		}
	}
	if !c.CitadelDryRun && len(c.CitadelHMACSecrets) == 0 {
		return errors.New("OPENCSIRT_CITADEL_HMAC_SECRETS must be set when CITADEL dry-run is disabled")
	}
	return nil
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func envBool(k string, d bool) bool {
	if v := os.Getenv(k); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return d
}

func envDuration(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if dur, err := time.ParseDuration(v); err == nil {
			return dur
		}
	}
	return d
}

func parseSecrets(s string) [][]byte {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, []byte(p))
		}
	}
	return out
}

// String redacts secrets for safe logging.
func (c *Config) String() string {
	return fmt.Sprintf("Config{HTTPAddr=%s Node=%s DevMode=%v DBMaxConns=%d "+
		"JWTSecretSet=%v CitadelDryRun=%v ThreatFlowInterval=%s OutboxTick=%s}",
		c.HTTPAddr, c.Node, c.DevMode, c.DBMaxConns,
		len(c.JWTSecret) > 0,
		c.CitadelDryRun, c.ThreatFlowInterval, c.OutboxTickInterval)
}
