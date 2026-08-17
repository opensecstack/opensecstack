// Package config loads VertGuard configuration from env + YAML via Viper.
//
// STATUS: Phase 4.1 scaffold. Fields expand as modules come online
// (Module 3 + 4 fields are active; Module 1/2/5 fields are stubs).
// See docs/configuration.md for the full reference.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/opensecstack/vertguard/internal/integrations/meetings"
)

// ErrInsecureProdConfig is returned by Config.EnforceProductionGate when
// the runtime environment looks like production but the loaded config
// carries dev-only / insecure defaults that would silently weaken the
// security posture (e.g. dev_mode=true, empty JWT secret).
//
// Closes security-checklist.md row 2.10 ("Refuse to start in prod with
// dev-mode on"). The gate is intentionally fail-closed: any single
// trigger aborts startup with the full list of reasons so operators
// can fix everything in one pass.
var ErrInsecureProdConfig = errors.New("insecure configuration in production environment")

// Config bundles every runtime knob. Nested structs keep the
// top-level flat; Viper's env mapping uses underscores.
type Config struct {
	Server     ServerConfig              `mapstructure:"server"`
	DB         DBConfig                  `mapstructure:"db"`
	Auth       AuthConfig                `mapstructure:"auth"`
	Citadel    CitadelConfig             `mapstructure:"citadel"`
	ThreatFlow ThreatFlowConfig          `mapstructure:"threatflow"`
	Prompt     PromptConfig              `mapstructure:"prompt"`
	ThreatFeed ThreatFeedConfig          `mapstructure:"threatfeed"`
	Media      MediaConfig               `mapstructure:"media"`
	Phishing   PhishingConfig            `mapstructure:"phishing"` // Phase 4.2
	Identity   IdentityConfig            `mapstructure:"identity"` // Phase 4.3
	ML         MLConfig                  `mapstructure:"ml"`       // Phase 4.2+
	IOC        IOCConfig                 `mapstructure:"ioc"`      // VG-006
	Webhook    WebhookConfig             `mapstructure:"webhook"`  // VG-015
	Meetings   []meetings.PlatformConfig // Phase 4.3 — meeting platform integrations
}

// WebhookConfig — VG-015 outbound webhook dispatcher tunables.
type WebhookConfig struct {
	Enabled             bool          `mapstructure:"enabled"`
	MaxRetries          int           `mapstructure:"max_retries"`
	BackoffBase         time.Duration `mapstructure:"backoff_base"`
	OutboxFlushInterval time.Duration `mapstructure:"outbox_flush_interval"`
	RequestTimeout      time.Duration `mapstructure:"request_timeout"`
}

// IOCConfig — VG-006 persistent IOC store + scheduled community-feed sync.
type IOCConfig struct {
	Enabled       bool           `mapstructure:"enabled"`
	Sources       []SourceConfig `mapstructure:"sources"`
	Allowlist     []string       `mapstructure:"allowlist"`
	SweepInterval time.Duration  `mapstructure:"sweep_interval"`
	// MISP / abuse.ch convenience knobs map to env vars without
	// requiring a YAML file. See Load() for the env→Sources composition.
	MISPURL        string        `mapstructure:"misp_url"`
	MISPToken      string        `mapstructure:"misp_token"`
	AbuseChEnabled bool          `mapstructure:"abusech_enabled"`
	AbuseChURLs    string        `mapstructure:"abusech_urls"`
	AbuseChHashes  string        `mapstructure:"abusech_hashes"`
	Interval       time.Duration `mapstructure:"interval"`
}

// SourceConfig — one community-feed adapter declared in YAML.
// Type ∈ misp|abusech|file.
type SourceConfig struct {
	Type       string        `mapstructure:"type"`
	Name       string        `mapstructure:"name"`
	URL        string        `mapstructure:"url"`
	HashURL    string        `mapstructure:"hash_url"`
	AuthHeader string        `mapstructure:"auth_header"`
	Path       string        `mapstructure:"path"`
	Interval   time.Duration `mapstructure:"interval"`
	Enabled    bool          `mapstructure:"enabled"`
}

// ServerConfig — HTTP listener settings.
type ServerConfig struct {
	Port             int           `mapstructure:"port"`
	DashboardPort    int           `mapstructure:"dashboard_port"`
	LogLevel         string        `mapstructure:"log_level"`
	ReadTimeout      time.Duration `mapstructure:"read_timeout"`
	WriteTimeout     time.Duration `mapstructure:"write_timeout"`
	RateLimitEnabled bool          `mapstructure:"rate_limit_enabled"`
	RateLimitRPS     float64       `mapstructure:"rate_limit_rps"`
	RateLimitBurst   int           `mapstructure:"rate_limit_burst"`
	// DrainGrace is the wait between flipping /readyz to 503 and calling
	// srv.Shutdown so the LB has time to stop sending new traffic.
	DrainGrace time.Duration `mapstructure:"drain_grace"`
	// TrustedProxyHops is the exact number of reverse proxies (LB / ingress)
	// between the public internet and this server. Zero (the default) means
	// "no trusted proxy" — the client IP used for rate limiting and audit
	// logging is read directly from the TCP connection (net/http's
	// r.RemoteAddr), which cannot be spoofed. Set this to the real hop
	// count only when the deployment actually sits behind that many
	// proxies that each unconditionally append to X-Forwarded-For — a
	// wrong count here lets an attacker forge the logged/rate-limited IP.
	// See internal/api.New's client-IP middleware wiring, and
	// GHSA-3fxj-6jh8-hvhx / GHSA-rjr7-jggh-pgcp / GHSA-9g5q-2w5x-hmxf for
	// the vulnerability this replaces (chi middleware.RealIP).
	TrustedProxyHops int `mapstructure:"trusted_proxy_hops"`
}

// DBConfig — PostgreSQL connection pool.
type DBConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	Name         string `mapstructure:"name"`
	User         string `mapstructure:"user"`
	Password     string `mapstructure:"password"`
	SSLMode      string `mapstructure:"ssl_mode"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
	// MinConns is the floor pgxpool keeps idle. When zero the db pkg
	// derives a default from MaxConns (see internal/db). Override via
	// VERTGUARD_DB_MIN_CONNS.
	MinConns int `mapstructure:"min_conns"`
}

// URL returns a Postgres connection string from the DB config.
func (d DBConfig) URL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.Name, d.SSLMode)
}

// AuthConfig — JWT HS256 auth (ecosystem-consistent).
//
// Dual-secret rotation: SecretNext lets the verifier accept tokens signed
// with the next-generation secret while the issuer still mints with the
// primary. SecretPrevious lets the verifier accept old tokens during a
// graceful drain after promotion. See docs/secrets-management.md.
//
// SinauthURL is the base URL of the sinauth OIDC issuer used for RS256 SSO
// token verification. Tokens carrying alg=RS256 are routed to sinauth; all
// other tokens use the HS256 Verifier. Defaults to http://localhost:8100 via
// VERTGUARD_AUTH_SINAUTH_URL.
type AuthConfig struct {
	Secret         string        `mapstructure:"secret"`
	SecretNext     string        `mapstructure:"secret_next"`     // pre-rollover: tokens may already be signed with this
	SecretPrevious string        `mapstructure:"secret_previous"` // post-rollover: tokens still in flight
	TokenTTL       time.Duration `mapstructure:"token_ttl"`
	Issuer         string        `mapstructure:"issuer"`
	DevMode        bool          `mapstructure:"dev_mode"`
	SinauthURL     string        `mapstructure:"sinauth_url"` // RS256 SSO issuer (sinauth)
}

// ActiveSecrets returns every non-empty secret in priority order:
// primary → next → previous. The verifier tries each until one validates;
// first match wins.
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

// ActiveSecretSlots returns the slot names corresponding to ActiveSecrets,
// in the same order. Useful for startup logging.
func (a AuthConfig) ActiveSecretSlots() []string {
	out := make([]string, 0, 3)
	if a.Secret != "" {
		out = append(out, "primary")
	}
	if a.SecretNext != "" {
		out = append(out, "next")
	}
	if a.SecretPrevious != "" {
		out = append(out, "previous")
	}
	return out
}

// CitadelConfig — upstream CITADEL integration.
//
// APIURL is the legacy field; BaseURL is the WORM-emit base preferred
// by the citadel client. If BaseURL is empty the client falls back to
// APIURL. KeySecret is the legacy HMAC secret; HMACSecret takes
// precedence if set. Enabled gates client construction at startup.
type CitadelConfig struct {
	APIURL     string `mapstructure:"api_url"`
	BaseURL    string `mapstructure:"base_url"`
	KeyID      string `mapstructure:"key_id"`
	KeySecret  string `mapstructure:"key_secret"`
	HMACSecret string `mapstructure:"hmac_secret"`
	// HMACSecrets / KeyIDs are the 3-slot rotation knobs ordered
	// [primary, next, previous]. Read from VERTGUARD_CITADEL_HMAC_SECRETS
	// / VERTGUARD_CITADEL_KEY_IDS as comma-separated lists. Mirrors the
	// JWT auth rotation contract.
	HMACSecrets []string `mapstructure:"hmac_secrets"`
	KeyIDs      []string `mapstructure:"key_ids"`
	ProjectID   string   `mapstructure:"project_id"`
	DryRun      bool     `mapstructure:"dry_run"`
	QueueMax    int      `mapstructure:"queue_max"`
	Enabled     bool     `mapstructure:"enabled"`
	AsyncBuffer int      `mapstructure:"async_buffer"`
}

// EffectiveHMACSecrets returns HMACSecrets when non-empty, else falls
// back to a 1-element slice containing EffectiveHMACSecret(). This lets
// the citadel client treat the multi-slot list as the canonical input
// without callers having to special-case the legacy single-key path.
func (c CitadelConfig) EffectiveHMACSecrets() []string {
	out := make([]string, 0, len(c.HMACSecrets))
	for _, s := range c.HMACSecrets {
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) > 0 {
		return out
	}
	if s := c.EffectiveHMACSecret(); s != "" {
		return []string{s}
	}
	return nil
}

// EffectiveKeyIDs returns KeyIDs when non-empty, else a 1-element slice
// containing KeyID. Aligned positionally with EffectiveHMACSecrets.
func (c CitadelConfig) EffectiveKeyIDs() []string {
	if len(c.KeyIDs) > 0 {
		return c.KeyIDs
	}
	if c.KeyID != "" {
		return []string{c.KeyID}
	}
	return nil
}

// CitadelHMACRotationCollision reports whether the operator set both
// the legacy scalar (HMACSecret/KeySecret) and the multi-slot
// HMACSecrets at the same time. main.go logs this loudly so the
// operator notices the ambiguity (the multi-slot list wins, but
// silently swallowing the scalar is exactly the kind of misconfig that
// causes confused debugging during a rotation drill).
func (c CitadelConfig) CitadelHMACRotationCollision() bool {
	hasScalar := c.HMACSecret != "" || c.KeySecret != ""
	hasMulti := false
	for _, s := range c.HMACSecrets {
		if s != "" {
			hasMulti = true
			break
		}
	}
	return hasScalar && hasMulti
}

// EffectiveBaseURL prefers BaseURL, falls back to APIURL.
func (c CitadelConfig) EffectiveBaseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return c.APIURL
}

// EffectiveHMACSecret prefers HMACSecret, falls back to KeySecret.
func (c CitadelConfig) EffectiveHMACSecret() string {
	if c.HMACSecret != "" {
		return c.HMACSecret
	}
	return c.KeySecret
}

// ThreatFlowConfig — bidirectional ThreatFlow integration.
type ThreatFlowConfig struct {
	APIURL        string `mapstructure:"api_url"`
	KeyID         string `mapstructure:"key_id"`
	KeySecret     string `mapstructure:"key_secret"`
	WebhookSecret string `mapstructure:"webhook_secret"`
}

// PromptConfig — Module 3 (Prompt Injection Defence).
type PromptConfig struct {
	CleanThreshold      float64 `mapstructure:"clean_threshold"`
	BlockThreshold      float64 `mapstructure:"block_threshold"`
	MaxInputSize        int64   `mapstructure:"max_input_size"`
	PatternRegistryPath string  `mapstructure:"pattern_registry_path"`
	CustomPatternsPath  string  `mapstructure:"custom_patterns_path"`
	NemoEndpoint        string  `mapstructure:"nemo_endpoint"`
	LlamaGuardEndpoint  string  `mapstructure:"llamaguard_endpoint"`

	// VG-003 v1.0 detector knobs. RulePackPath points at the JSON rule
	// pack shipped under internal/prompt/rules/v1.json. MLBinaryPath /
	// MLTimeout configure the subprocess MLBackend; an empty
	// MLBinaryPath disables ML entirely. MaxInputBytes is the v1.0
	// alias for MaxInputSize (kept separate so operators can ratchet
	// down the regex-engine cap without touching the global cap).
	RulePackPath  string        `mapstructure:"rule_pack_path"`
	MLBinaryPath  string        `mapstructure:"ml_binary_path"`
	MLTimeout     time.Duration `mapstructure:"ml_timeout"`
	MaxInputBytes int           `mapstructure:"max_input_bytes"`
}

// Prompt module sizing bounds. The lower bound rejects nonsensical
// caps that would refuse the smallest legitimate prompt; the upper
// bound prevents accidental denial-of-service via a huge regex pass.
const (
	promptMaxInputSizeMin     int64 = 1 << 10  // 1 KiB
	promptMaxInputSizeMax     int64 = 16 << 20 // 16 MiB
	promptMaxInputSizeDefault int64 = 1 << 20  // 1 MiB
)

// ApplyDefaults normalises the prompt config in-place. A zero
// MaxInputSize is replaced with the documented 1 MiB default so the
// scanner's `if maxInputBytes > 0` check is never silently disabled.
func (p *PromptConfig) ApplyDefaults() {
	if p.MaxInputSize == 0 {
		p.MaxInputSize = promptMaxInputSizeDefault
	}
	// Mirror the Viper defaults applied in setDefaults so a zero-value
	// PromptConfig (e.g. constructed in a test) validates cleanly. Real
	// startups go through Load → setDefaults first; this branch only
	// fires when ApplyDefaults is called against a freshly-zeroed
	// struct.
	if p.CleanThreshold == 0 && p.BlockThreshold == 0 {
		p.CleanThreshold = 0.3
		p.BlockThreshold = 0.7
	}
}

// Validate checks the prompt config against the documented bounds.
// Returns a non-nil error when the operator supplied a value that
// would weaken the security posture (negative caps, absurdly small or
// huge limits, inverted thresholds).
func (p PromptConfig) Validate() error {
	if p.MaxInputSize < promptMaxInputSizeMin || p.MaxInputSize > promptMaxInputSizeMax {
		return fmt.Errorf("prompt.max_input_size=%d out of bounds [%d, %d]",
			p.MaxInputSize, promptMaxInputSizeMin, promptMaxInputSizeMax)
	}
	if p.CleanThreshold < 0 || p.CleanThreshold > 1 {
		return fmt.Errorf("prompt.clean_threshold=%v out of [0,1]", p.CleanThreshold)
	}
	if p.BlockThreshold < 0 || p.BlockThreshold > 1 {
		return fmt.Errorf("prompt.block_threshold=%v out of [0,1]", p.BlockThreshold)
	}
	if p.CleanThreshold >= p.BlockThreshold {
		return fmt.Errorf("prompt.clean_threshold (%v) must be < prompt.block_threshold (%v)",
			p.CleanThreshold, p.BlockThreshold)
	}
	return nil
}

// ThreatFeedConfig — Module 4 (AI Threat Intelligence Feed).
type ThreatFeedConfig struct {
	SourcesPath       string        `mapstructure:"sources_path"`
	AtlasSyncCron     string        `mapstructure:"atlas_sync_cron"`
	CommunitySyncCron string        `mapstructure:"community_sync_cron"`
	PushInterval      time.Duration `mapstructure:"push_interval"`
	ReconcileCron     string        `mapstructure:"reconcile_cron"`
	MinConfidence     float64       `mapstructure:"min_confidence"`
	// AtlasSourceURL overrides the upstream MITRE ATLAS YAML location.
	// Empty means: fall back to VERTGUARD_ATLAS_SOURCE_URL env, then to
	// atlas.DefaultSourceURL. See internal/threatfeed/atlas/sync.go.
	AtlasSourceURL string `mapstructure:"atlas_source_url"`
}

// MediaConfig — Module 1 (Media Authenticity).
//
// Phase 4.2: BinaryPath points at the compiled c2pa-verify CLI; Timeout
// caps each subprocess invocation. C2PATrustStore is forwarded to the
// CLI via --trust-store when set (see docs/c2pa-trust-store.md).
type MediaConfig struct {
	BinaryPath       string        `mapstructure:"binary_path"`
	Timeout          time.Duration `mapstructure:"timeout"`
	C2PATrustStore   string        `mapstructure:"c2pa_truststore"`
	C2PAOCSPEnabled  bool          `mapstructure:"c2pa_ocsp_enabled"`
	MaxSize          int64         `mapstructure:"max_size"`
	ContentRetention bool          `mapstructure:"content_retention"`

	// VG-011-c — configurable trust anchor list + revocation handling.
	// TrustAnchorsDir holds PEM anchors (one per file or a bundle).
	// RevocationListPath is a CRL (PEM or DER). ReloadInterval governs
	// the mtime-poll frequency for both. RequireTrust=true makes the
	// handler return 422 instead of 200 when the verdict is
	// untrusted/revoked (default false for migration).
	TrustAnchorsDir    string        `mapstructure:"trust_anchors_dir"`
	RevocationListPath string        `mapstructure:"revocation_list_path"`
	ReloadInterval     time.Duration `mapstructure:"reload_interval"`
	RequireTrust       bool          `mapstructure:"require_trust"`
}

// PhishingConfig — Module 5 (Phase 4.2, rule-based v1).
type PhishingConfig struct {
	Enabled        bool    `mapstructure:"enabled"`
	ModelsPath     string  `mapstructure:"models_path"`
	CleanThreshold float64 `mapstructure:"clean_threshold"`
	BlockThreshold float64 `mapstructure:"block_threshold"`
	MaxInputSize   int64   `mapstructure:"max_input_size"`
}

// IdentityConfig — Module 6 (Identity Verification, rule-based v1).
type IdentityConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	RealtimeEnabled bool          `mapstructure:"realtime_enabled"` // Phase 4.3 ML
	CleanThreshold  float64       `mapstructure:"clean_threshold"`
	BlockThreshold  float64       `mapstructure:"block_threshold"`
	MaxInputSize    int64         `mapstructure:"max_input_size"`
	ReplayWindow    time.Duration `mapstructure:"replay_window"`
	ReplayThreshold int           `mapstructure:"replay_threshold"`
	PatternsPath    string        `mapstructure:"patterns_path"`
}

// MLConfig — Python gRPC ML service (Phase 4.2+).
//
// Enabled is the master kill switch. AlwaysScore flips the scanners
// from "ML on SUSPICIOUS only" (the default; cheapest hot-path) to
// "ML on every request" (eval mode — measure ML accuracy in
// production traffic). Timeout caps each ML RPC; the breaker trips
// after 5 consecutive timeouts/errors.
type MLConfig struct {
	GRPCURL      string        `mapstructure:"grpc_url"`
	ModelsPath   string        `mapstructure:"models_path"`
	GPUEnabled   bool          `mapstructure:"gpu_enabled"`
	MaxBatchSize int           `mapstructure:"max_batch_size"`
	Enabled      bool          `mapstructure:"enabled"`
	Timeout      time.Duration `mapstructure:"timeout"`
	AlwaysScore  bool          `mapstructure:"always_score"`
}

// Load reads configuration from environment (prefix VERTGUARD_) plus
// optional YAML via VERTGUARD_CONFIG_PATH.
func Load() (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix("VERTGUARD")
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

	// Viper's env binding does not split CSV strings into []string fields
	// reliably; handle the rotation knobs manually so
	// VERTGUARD_CITADEL_HMAC_SECRETS="primary,next,previous" works as
	// documented. Empty entries are filtered.
	if raw := os.Getenv("VERTGUARD_CITADEL_HMAC_SECRETS"); raw != "" {
		cfg.Citadel.HMACSecrets = splitCSV(raw)
	}
	if raw := os.Getenv("VERTGUARD_CITADEL_KEY_IDS"); raw != "" {
		cfg.Citadel.KeyIDs = splitCSV(raw)
	}
	// Same CSV-via-env trick for the IOC allowlist (CIDRs + domains).
	if raw := os.Getenv("VERTGUARD_IOC_ALLOWLIST"); raw != "" {
		cfg.IOC.Allowlist = splitCSV(raw)
	}

	// VG-003 dedicated env aliases. Operators expect short names
	// (PROMPT_RULES_PATH, PROMPT_ML_BINARY) rather than the full nested
	// keys produced by viper's AutomaticEnv path.
	if raw := os.Getenv("VERTGUARD_PROMPT_RULES_PATH"); raw != "" {
		cfg.Prompt.RulePackPath = raw
	}
	if raw := os.Getenv("VERTGUARD_PROMPT_ML_BINARY"); raw != "" {
		cfg.Prompt.MLBinaryPath = raw
	}
	if raw := os.Getenv("VERTGUARD_PROMPT_ML_TIMEOUT"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.Prompt.MLTimeout = d
		}
	}

	// Phase 4.3 — meeting platform credentials loaded from dedicated env
	// vars. Viper's nested-struct unmarshalling does not handle a []struct
	// that varies by platform key, so we build the slice manually from
	// the three VERTGUARD_MEETING_<PLATFORM>_* env triplets.
	cfg.Meetings = loadMeetingPlatforms()

	// Normalise the prompt section before any consumer reads it. The
	// scanner treats max_input_size <= 0 as "unbounded", so an empty
	// value would silently disable the cap. ApplyDefaults restores the
	// 1 MiB default; Validate then enforces the documented bounds.
	cfg.Prompt.ApplyDefaults()
	if err := cfg.Prompt.Validate(); err != nil {
		return nil, fmt.Errorf("validate prompt config: %w", err)
	}

	return &cfg, nil
}

// loadMeetingPlatforms builds the []meetings.PlatformConfig slice from the
// VERTGUARD_MEETING_<PLATFORM>_{CLIENT_ID,CLIENT_SECRET,WEBHOOK_SECRET} env
// triplets. A platform entry is included (with Enabled=true) whenever its
// CLIENT_ID is non-empty; an entry is always appended for each of the three
// known platforms so Status reports them even when unconfigured.
func loadMeetingPlatforms() []meetings.PlatformConfig {
	type envSet struct {
		platform      meetings.MeetingPlatform
		clientID      string
		clientSecret  string
		webhookSecret string
	}
	sets := []envSet{
		{
			platform:      meetings.PlatformZoom,
			clientID:      os.Getenv("VERTGUARD_MEETING_ZOOM_CLIENT_ID"),
			clientSecret:  os.Getenv("VERTGUARD_MEETING_ZOOM_CLIENT_SECRET"),
			webhookSecret: os.Getenv("VERTGUARD_MEETING_ZOOM_WEBHOOK_SECRET"),
		},
		{
			platform:      meetings.PlatformTeams,
			clientID:      os.Getenv("VERTGUARD_MEETING_TEAMS_CLIENT_ID"),
			clientSecret:  os.Getenv("VERTGUARD_MEETING_TEAMS_CLIENT_SECRET"),
			webhookSecret: os.Getenv("VERTGUARD_MEETING_TEAMS_WEBHOOK_SECRET"),
		},
		{
			platform:      meetings.PlatformWebEx,
			clientID:      os.Getenv("VERTGUARD_MEETING_WEBEX_CLIENT_ID"),
			clientSecret:  os.Getenv("VERTGUARD_MEETING_WEBEX_CLIENT_SECRET"),
			webhookSecret: os.Getenv("VERTGUARD_MEETING_WEBEX_WEBHOOK_SECRET"),
		},
	}

	out := make([]meetings.PlatformConfig, 0, len(sets))
	for _, s := range sets {
		out = append(out, meetings.PlatformConfig{
			Platform:      s.platform,
			ClientID:      s.clientID,
			ClientSecret:  s.clientSecret,
			WebhookSecret: s.webhookSecret,
			Enabled:       s.clientID != "",
		})
	}
	return out
}

// splitCSV splits a comma-separated env value, trims whitespace and
// drops empty fields. Local helper for the multi-slot rotation knobs
// in CitadelConfig.
func splitCSV(s string) []string {
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

// IsProductionEnv reports whether the process appears to be running in
// a production environment.
//
// Signal hierarchy (first match wins):
//  1. VG_ENV (explicit) — "production" / "prod" → true; anything else → false.
//  2. GO_ENV (legacy) — same matching rules.
//
// If neither is set we deliberately return false so local `go run` and
// CI never trip the production gate. Operators must opt in by setting
// VG_ENV=production in their deployment manifests; the Helm chart in
// deploy/helm/vertguard sets this on the API Deployment by default.
func IsProductionEnv() bool {
	for _, key := range []string{"VG_ENV", "GO_ENV"} {
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

// EnforceProductionGate refuses to start when the environment looks like
// production but the loaded config carries dev-only / insecure
// defaults. Returns nil in non-prod environments (warnings still flow
// via WarnIfInsecure).
//
// Closes security-checklist.md row 2.10. The signals are kept narrow
// and concrete so the gate has no false positives for sane prod
// configs:
//
//   - auth.dev_mode=true                 → JWT bypass; never valid in prod.
//   - auth.secret=""                      → unsigned/HS256-with-empty-key.
//   - db.ssl_mode="disable"               → cleartext Postgres traffic.
//
// Each trigger is reported in the returned error so operators see the
// full remediation list rather than playing whack-a-mole.
func (c *Config) EnforceProductionGate() error {
	if !IsProductionEnv() {
		return nil
	}
	var reasons []string
	if c.Auth.DevMode {
		reasons = append(reasons, "auth.dev_mode=true (VERTGUARD_AUTH_DEV_MODE) — JWT verification is bypassed; refusing to start")
	}
	if c.Auth.Secret == "" {
		reasons = append(reasons, "auth.secret is empty (VERTGUARD_AUTH_SECRET) — JWT signing key missing; refusing to start")
	}
	if strings.EqualFold(c.DB.SSLMode, "disable") {
		reasons = append(reasons, "db.ssl_mode=disable (VERTGUARD_DB_SSL_MODE) — Postgres traffic would be cleartext; set 'require' or 'verify-full'")
	}
	// Normalise zero-value MaxInputSize to the documented default
	// before validating: operators who never touched this knob (the
	// common case) shouldn't be told their config is invalid because
	// EnforceProductionGate ran on a Config that bypassed Load's
	// ApplyDefaults (e.g. constructed in a test).
	promptCfg := c.Prompt
	promptCfg.ApplyDefaults()
	if err := promptCfg.Validate(); err != nil {
		reasons = append(reasons, "prompt config invalid: "+err.Error())
	}
	if len(reasons) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInsecureProdConfig, strings.Join(reasons, "; "))
}

// WarnIfInsecure returns a list of startup warnings for fields that
// suggest a non-production configuration. Callers log these loudly.
func (c *Config) WarnIfInsecure() []string {
	var warns []string

	if c.Auth.Secret == "" {
		warns = append(warns, "VERTGUARD_AUTH_SECRET is empty — dev mode enabled; NEVER run this way in production")
	}
	if c.Auth.DevMode {
		warns = append(warns, "VERTGUARD_AUTH_DEV_MODE is true — authentication bypassed")
	}
	if c.Auth.SecretNext != "" {
		warns = append(warns, "VERTGUARD_AUTH_SECRET_NEXT is set — JWT secret rotation in progress; promote when ready (set _SECRET=$_NEXT and clear _NEXT)")
	}
	if c.Auth.SecretPrevious != "" {
		warns = append(warns, "VERTGUARD_AUTH_SECRET_PREVIOUS is set — verifier still accepting previous-generation tokens; clear after the drain window (max(token_ttl, 24h)) elapses")
	}
	if c.DB.SSLMode == "disable" {
		warns = append(warns, "VERTGUARD_DB_SSL_MODE is 'disable' — use 'require' or 'verify-full' in production")
	}
	if c.Citadel.APIURL == "" {
		warns = append(warns, "VERTGUARD_CITADEL_API_URL is empty — running in standalone mode; detections will NOT be WORM-logged")
	}
	if c.ThreatFlow.APIURL == "" {
		warns = append(warns, "VERTGUARD_THREATFLOW_API_URL is empty — AI IOCs will NOT be pushed to ThreatFlow")
	}
	if c.ML.Enabled && c.ML.GRPCURL == "" {
		warns = append(warns, "VERTGUARD_ML_ENABLED is true but VERTGUARD_ML_GRPC_URL is empty — ML enricher will be skipped")
	}

	return warns
}
