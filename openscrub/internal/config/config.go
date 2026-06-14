// Package config loads OpenScrub control-plane configuration from
// environment variables. Mirrors the cyberpath / irflow pattern: 12-factor,
// flat OPENSCRUB_* names, with safe defaults so a fresh checkout boots.
package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultPasswordPepper is the placeholder pepper used when
// OPENSCRUB_PASSWORD_PEPPER is unset. It exists so a fresh `make
// compose-up` works without manual env setup, but Validate() refuses
// to keep running with this literal value when DevMode is false — see
// PasswordPepperIsDefault and Config.Validate.
const DefaultPasswordPepper = "openscrub-default-pepper-CHANGE-ME"

// ErrInsecureDefaults is returned by Validate when the daemon would
// boot in a non-dev configuration but is still using a build-time
// default that operators are required to override.
var ErrInsecureDefaults = errors.New("config: insecure default detected")

// Config is the runtime configuration bag.
type Config struct {
	// Listen address (host:port). Default ":8087" per
	// docs/deployment-topology.md.
	HTTPAddr string

	// Postgres URL. Empty = use the in-memory store (dev only).
	DBURL string
	// DBMaxConns caps the pgxpool size. Defaults to 16 (matching the
	// guidance in docs/configuration.md). Increase for high-throughput
	// deployments alongside Postgres' max_connections.
	DBMaxConns int32

	// JWT — HS256 secret(s), comma-separated for rotation
	// (primary,next,previous). Empty = dev mode (auth tolerated).
	JWTSecrets []string
	JWTIssuer  string
	DevMode    bool

	// ThreatFlow IOC puller.
	ThreatFlowURL      string
	ThreatFlowToken    string
	ThreatFlowInterval time.Duration

	// CITADEL evidence emitter.
	CitadelURL string
	// CitadelKeySecret is the legacy single-key knob.
	CitadelKeySecret string
	// CitadelKeySecrets is the 3-slot rotation list
	// (primary,next,previous) parsed from
	// OPENSCRUB_CITADEL_HMAC_SECRETS. Mirrors the JWT rotation
	// convention. When set, takes precedence over CitadelKeySecret.
	CitadelKeySecrets []string
	CitadelKeyID      string
	// CitadelKeyIDs aligns with CitadelKeySecrets[i].
	CitadelKeyIDs []string
	CitadelDryRun bool
	NodeName      string

	// Mitigation gating — minimum duration before a mitigation event is
	// emitted to CITADEL. Default 5s per the prompt.
	MitigationMinDuration time.Duration

	// Dataplane transport. "noop" (default), "uds" (Unix-socket RPC).
	DataplaneTransport string
	DataplaneSocket    string

	// Login issuer credentials. UsersSpec is the comma-separated
	// "user:role:sha256hex" list parsed by auth.NewCredentialStore.
	// PasswordPepper is mixed into every hash. TokenTTL bounds session
	// lifetime. Empty UsersSpec disables /api/v1/auth/login (operators
	// then mint JWTs out-of-band against OPENSCRUB_JWT_SECRET).
	UsersSpec      string
	PasswordPepper string
	TokenTTL       time.Duration

	// SinauthURL is the base URL of the sinauth OIDC issuer used for
	// RS256 SSO token verification. Defaults to http://localhost:8100.
	// When a Bearer token carries alg=RS256 the auth middleware routes
	// it to the sinauth SDK instead of the local HS256 verifier.
	SinauthURL string
}

// FromEnv reads OPENSCRUB_* environment variables.
func FromEnv() Config {
	return Config{
		HTTPAddr:              envDefault("OPENSCRUB_HTTP_ADDR", ":8087"),
		DBURL:                 os.Getenv("OPENSCRUB_DB_URL"),
		DBMaxConns:            int32(envIntOrDefault("OPENSCRUB_DB_MAX_CONNS", 16)),
		JWTSecrets:            splitCSV(os.Getenv("OPENSCRUB_JWT_SECRET")),
		JWTIssuer:             envDefault("OPENSCRUB_JWT_ISSUER", "openscrub"),
		DevMode:               envBool("OPENSCRUB_DEV_MODE", false),
		ThreatFlowURL:         os.Getenv("OPENSCRUB_THREATFLOW_API_URL"),
		ThreatFlowToken:       os.Getenv("OPENSCRUB_THREATFLOW_TOKEN"),
		ThreatFlowInterval:    envDuration("OPENSCRUB_THREATFLOW_INTERVAL", 15*time.Minute),
		CitadelURL:            os.Getenv("OPENSCRUB_CITADEL_API_URL"),
		CitadelKeySecret:      os.Getenv("OPENSCRUB_CITADEL_HMAC_SECRET"),
		CitadelKeySecrets:     splitCSV(os.Getenv("OPENSCRUB_CITADEL_HMAC_SECRETS")),
		CitadelKeyID:          os.Getenv("OPENSCRUB_CITADEL_KEY_ID"),
		CitadelKeyIDs:         splitCSV(os.Getenv("OPENSCRUB_CITADEL_KEY_IDS")),
		CitadelDryRun:         envBool("OPENSCRUB_CITADEL_DRY_RUN", false),
		NodeName:              envDefault("OPENSCRUB_NODE", hostnameOr("openscrub-edge")),
		MitigationMinDuration: envDuration("OPENSCRUB_MITIGATION_MIN_DURATION", 5*time.Second),
		DataplaneTransport:    envDefault("OPENSCRUB_DATAPLANE_TRANSPORT", "noop"),
		DataplaneSocket:       envDefault("OPENSCRUB_DATAPLANE_SOCKET", "/run/openscrub/dataplane.sock"),
		UsersSpec:             os.Getenv("OPENSCRUB_USERS"),
		PasswordPepper:        envDefault("OPENSCRUB_PASSWORD_PEPPER", DefaultPasswordPepper),
		TokenTTL:              envDuration("OPENSCRUB_TOKEN_TTL", time.Hour),
		SinauthURL:            envDefault("SINAUTH_URL", "http://localhost:8100"),
	}
}

// PasswordPepperIsDefault reports whether the active pepper is the
// build-time placeholder. Wrapped in a helper so the comparison is
// done in one place if the default ever changes.
func (c Config) PasswordPepperIsDefault() bool {
	return c.PasswordPepper == DefaultPasswordPepper
}

// Validate enforces invariants that cannot be expressed as a
// per-field default. Today this is exactly one rule: refuse to boot
// the auth issuer with the literal placeholder pepper unless the
// operator has explicitly opted into dev mode. The pepper is mixed
// into every login hash; running production with a public default
// reduces the operator's password storage to plain SHA-256 and
// invalidates the entire credential-store threat model.
//
// Validate only fires when /auth/login would actually be enabled
// (UsersSpec is set) — operators who mint JWTs out-of-band are not
// affected by the pepper.
func (c Config) Validate() error {
	if !c.DevMode && c.UsersSpec != "" && c.PasswordPepperIsDefault() {
		return errors.Join(ErrInsecureDefaults, errors.New(
			"OPENSCRUB_PASSWORD_PEPPER is the build-time default and "+
				"OPENSCRUB_USERS is set; refusing to start. Set "+
				"OPENSCRUB_PASSWORD_PEPPER to a high-entropy secret, or "+
				"set OPENSCRUB_DEV_MODE=1 to override (dev only)"))
	}
	return nil
}

func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hostnameOr(def string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return def
}
