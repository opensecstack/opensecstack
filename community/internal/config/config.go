package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func Load() (*Config, error) {
	cfg := &Config{
		HTTPAddr:      env("COMMUNITY_HTTP_ADDR", ":8090"),
		Node:          env("COMMUNITY_NODE", "community-0"),
		DevMode:       envBool("COMMUNITY_DEV_MODE", false),
		DBURL:         env("COMMUNITY_DB_URL", ""),
		DBMaxConns:    int32(envInt("COMMUNITY_DB_MAX_CONNS", 16)),
		JWTSecret:     env("COMMUNITY_JWT_SECRET", ""),
		JWTIssuer:     env("COMMUNITY_JWT_ISSUER", "community"),
		TokenTTL:      envDuration("COMMUNITY_TOKEN_TTL", 12*time.Hour),
		Pepper:        env("COMMUNITY_PASSWORD_PEPPER", ""),
		CitadelURL:    env("COMMUNITY_CITADEL_API_URL", ""),
		CitadelKeyID:  env("COMMUNITY_CITADEL_KEY_ID", "community-1"),
		CitadelDryRun: envBool("COMMUNITY_CITADEL_DRY_RUN", true),
	}

	if raw := env("COMMUNITY_CITADEL_HMAC_SECRETS", ""); raw != "" {
		cfg.CitadelHMAC = strings.Split(raw, ",")
	}

	cfg.InviteOnly = envBool("COMMUNITY_INVITE_ONLY", false)
	// Native email/password auth is on by default (community is the public hub).
	// Set COMMUNITY_NATIVE_AUTH=false in an integrated SIN deployment to make
	// sinauth SSO the only way in.
	cfg.NativeAuthEnabled = envBool("COMMUNITY_NATIVE_AUTH", true)
	if raw := env("COMMUNITY_ALLOWED_EMAIL_DOMAINS", ""); raw != "" {
		cfg.AllowedEmailDomains = strings.Split(raw, ",")
	}

	cfg.MeilisearchURL = env("MEILISEARCH_URL", "http://localhost:7700")
	cfg.MeilisearchKey = env("MEILISEARCH_KEY", "")
	cfg.UploadDir = env("UPLOAD_DIR", "./uploads")

	cfg.GitHubClientID     = env("GITHUB_CLIENT_ID", "")
	cfg.GitHubClientSecret = env("GITHUB_CLIENT_SECRET", "")
	cfg.GitHubCallbackURL  = env("GITHUB_CALLBACK_URL", "https://sin.to/api/v1/auth/github/callback")

	cfg.GoogleClientID     = env("GOOGLE_CLIENT_ID", "")
	cfg.GoogleClientSecret = env("GOOGLE_CLIENT_SECRET", "")
	cfg.GoogleRedirectURI  = env("GOOGLE_REDIRECT_URI", "https://sin.to/api/v1/auth/google/callback")

	cfg.SinauthURL          = env("SINAUTH_URL", "http://localhost:8100")
	// SinauthPublicURL is the browser-facing sinauth origin used for the
	// /oauth/authorize redirect. In Docker the server reaches sinauth via an
	// in-network name (e.g. http://sinauth-api:8100 or http://host.docker.internal:8100)
	// that a user's browser cannot resolve, so the authorize redirect must use a
	// host-reachable URL. Defaults to SinauthURL for single-host deployments.
	cfg.SinauthPublicURL    = env("SINAUTH_PUBLIC_URL", cfg.SinauthURL)
	cfg.SinauthClientID     = env("SINAUTH_CLIENT_ID", "")
	cfg.SinauthClientSecret = env("SINAUTH_CLIENT_SECRET", "")
	cfg.SinauthCallbackURL  = env("SINAUTH_CALLBACK_URL", "https://sin.to/api/v1/auth/sinauth/callback")

	cfg.SMTPHost     = env("SMTP_HOST", "")
	cfg.SMTPPort     = envInt("SMTP_PORT", 587)
	cfg.SMTPUsername = env("SMTP_USERNAME", "")
	cfg.SMTPPassword = env("SMTP_PASSWORD", "")
	cfg.SMTPFrom     = env("SMTP_FROM", "noreply@sin.to")
	cfg.SiteURL      = env("SITE_URL", "http://localhost:5173")
	cfg.DigestEnabled = envBool("DIGEST_ENABLED", true)

	if raw := env("COMMUNITY_TRUSTED_PROXIES", ""); raw != "" {
		cfg.TrustedProxies = strings.Split(raw, ",")
	}
	if raw := env("COMMUNITY_ALLOWED_ORIGINS", ""); raw != "" {
		cfg.AllowedOrigins = strings.Split(raw, ",")
	}

	if raw := env("COMMUNITY_USERS", ""); raw != "" {
		for _, entry := range strings.Split(raw, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), ":", 3)
			if len(parts) != 3 {
				return nil, fmt.Errorf("invalid COMMUNITY_USERS entry: %q", entry)
			}
			cfg.Users = append(cfg.Users, UserEntry{
				Username: parts[0],
				Role:     parts[1],
				Hash:     parts[2],
			})
		}
	}

	if !cfg.DevMode {
		if cfg.DBURL == "" {
			return nil, errors.New("COMMUNITY_DB_URL is required outside dev mode")
		}
		if len(cfg.JWTSecret) < 32 {
			return nil, errors.New("COMMUNITY_JWT_SECRET must be >= 32 bytes outside dev mode")
		}
		if strings.Contains(cfg.Pepper, "do-not-use-in-prod") {
			return nil, errors.New("COMMUNITY_PASSWORD_PEPPER contains dev sentinel")
		}
	}

	return cfg, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
