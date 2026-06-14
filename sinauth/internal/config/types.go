package config

import "time"

type Config struct {
	HTTPAddr   string
	DevMode    bool
	DBURL      string
	DBMaxConns int32

	// JWT / token signing
	SigningKeyPath  string        // path to PEM private key file
	SigningKeyID    string        // kid for JWKS
	// DefaultRole is the primary role granted in issued access tokens when a
	// user has no explicit per-client RBAC role assignment. Keeps prod least-
	// privilege (default "viewer"); dev sets it to "admin" via SINAUTH_DEFAULT_ROLE.
	DefaultRole     string
	AccessTokenTTL  time.Duration
	IDTokenTTL      time.Duration
	RefreshTokenTTL time.Duration

	// Issuer — used in OIDC discovery and token claims
	Issuer string // e.g. https://auth.sin.to

	// Social OAuth
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string
	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURI  string

	// Email
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	// Security
	BcryptCost           int
	TrustedProxies       []string
	AllowedOrigins       []string
	RateLimitAuthPerMin  int // per-IP limit on auth endpoints (login/register/etc.)
	RateLimitGlobalPerMin int // per-IP global limit across all endpoints

	// Site
	SiteURL string

	// SMS / Twilio
	TwilioSID   string
	TwilioToken string
	TwilioFrom  string
	SMSEnabled  bool

	// WebAuthn / FIDO2
	WebAuthnRPID          string   // e.g. "sin.to"
	WebAuthnRPDisplayName string   // e.g. "SIN"
	WebAuthnOrigins       []string // e.g. ["https://sin.to"]
}
