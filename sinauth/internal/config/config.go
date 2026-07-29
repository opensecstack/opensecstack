package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Load reads configuration from environment variables and returns a validated Config.
func Load() (*Config, error) {
	cfg := &Config{
		HTTPAddr:        env("SINAUTH_HTTP_ADDR", ":8100"),
		DevMode:         envBool("SINAUTH_DEV_MODE", false),
		DBURL:           env("SINAUTH_DB_URL", ""),
		DBMaxConns:      int32(envInt("SINAUTH_DB_MAX_CONNS", 20)),
		SigningKeyPath:  env("SINAUTH_SIGNING_KEY_PATH", ""),
		SigningKeyID:    env("SINAUTH_SIGNING_KEY_ID", "default"),
		DefaultRole:     env("SINAUTH_DEFAULT_ROLE", "viewer"),
		AccessTokenTTL:  envDuration("SINAUTH_ACCESS_TOKEN_TTL", time.Hour),
		IDTokenTTL:      envDuration("SINAUTH_ID_TOKEN_TTL", 5*time.Minute),
		RefreshTokenTTL: envDuration("SINAUTH_REFRESH_TOKEN_TTL", 720*time.Hour),
		Issuer:          env("SINAUTH_ISSUER", ""),
		SiteURL:         env("SINAUTH_SITE_URL", ""),

		BootstrapAdminEmail: env("SINAUTH_BOOTSTRAP_ADMIN_EMAIL", ""),

		SMTPHost:     env("SINAUTH_SMTP_HOST", ""),
		SMTPPort:     envInt("SINAUTH_SMTP_PORT", 587),
		SMTPUsername: env("SINAUTH_SMTP_USERNAME", ""),
		SMTPPassword: env("SINAUTH_SMTP_PASSWORD", ""),
		SMTPFrom:     env("SINAUTH_SMTP_FROM", ""),

		BcryptCost:            envInt("SINAUTH_BCRYPT_COST", 12),
		TrustedProxies:        envCSV("SINAUTH_TRUSTED_PROXIES"),
		AllowedOrigins:        envCSV("SINAUTH_ALLOWED_ORIGINS"),
		RateLimitAuthPerMin:   envInt("SINAUTH_RATE_LIMIT_AUTH", 5),
		RateLimitGlobalPerMin: envInt("SINAUTH_RATE_LIMIT_GLOBAL", 120),

		GoogleClientID:     env("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: env("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURI:  env("GOOGLE_REDIRECT_URI", ""),
		GitHubClientID:     env("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret: env("GITHUB_CLIENT_SECRET", ""),
		GitHubRedirectURI:  env("GITHUB_REDIRECT_URI", ""),

		TwilioSID:   env("TWILIO_ACCOUNT_SID", ""),
		TwilioToken: env("TWILIO_AUTH_TOKEN", ""),
		TwilioFrom:  env("TWILIO_FROM", ""),

		WebAuthnRPID:          env("SINAUTH_WEBAUTHN_RP_ID", "localhost"),
		WebAuthnRPDisplayName: env("SINAUTH_WEBAUTHN_RP_DISPLAY", "SIN"),

		PermifyURL:     env("SINAUTH_PERMIFY_URL", ""),
		PermifyTimeout: envDuration("SINAUTH_PERMIFY_TIMEOUT", 3*time.Second),
	}

	cfg.SMSEnabled = cfg.TwilioSID != ""
	cfg.PermifyEnabled = cfg.PermifyURL != ""

	// Default the social OAuth redirect URIs to the canonical callback routes
	// under the issuer, so social login works with only the client ID/secret set.
	// These must exactly match the callback routes registered in the API server
	// (GET /api/v1/auth/{provider}/callback) and the URLs registered in the
	// Google / GitHub OAuth app consoles.
	if base := strings.TrimRight(cfg.Issuer, "/"); base != "" {
		if cfg.GoogleRedirectURI == "" {
			cfg.GoogleRedirectURI = base + "/api/v1/auth/google/callback"
		}
		if cfg.GitHubRedirectURI == "" {
			cfg.GitHubRedirectURI = base + "/api/v1/auth/github/callback"
		}
	}

	if raw := env("SINAUTH_WEBAUTHN_ORIGINS", ""); raw != "" {
		cfg.WebAuthnOrigins = strings.Split(raw, ",")
		for i, o := range cfg.WebAuthnOrigins {
			cfg.WebAuthnOrigins[i] = strings.TrimSpace(o)
		}
	} else {
		cfg.WebAuthnOrigins = []string{"http://localhost:5173"}
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	return cfg, nil
}

// validate enforces required fields when not running in dev mode.
func validate(cfg *Config) error {
	if cfg.DevMode {
		return nil
	}

	var errs []string

	if cfg.DBURL == "" {
		errs = append(errs, "SINAUTH_DB_URL is required")
	}
	if cfg.Issuer == "" {
		errs = append(errs, "SINAUTH_ISSUER is required")
	}
	if cfg.SigningKeyPath == "" {
		errs = append(errs, "SINAUTH_SIGNING_KEY_PATH is required")
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

// env returns the value of the environment variable key, or fallback if unset/empty.
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envInt parses an integer environment variable, returning fallback on parse failure or absence.
func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// envBool parses a boolean environment variable ("true", "1", "yes" are truthy).
func envBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	return v == "true" || v == "1" || v == "yes"
}

// envDuration parses a time.Duration environment variable.
func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

// envCSV splits a comma-separated environment variable into a string slice.
// Returns nil if the variable is unset or empty.
func envCSV(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
