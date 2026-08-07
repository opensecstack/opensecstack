// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package config

import "time"

// Config holds all runtime configuration for the SecureLab service.
type Config struct {
	// HTTPAddr is the TCP address the HTTP server binds to.
	// Default: ":8085"
	HTTPAddr string

	// DevMode disables strict validation checks (JWT secret length,
	// CitadelHMACSecrets requirement). Never enable in production.
	DevMode bool

	// DBUrl is the PostgreSQL connection string (DSN or URL format).
	DBUrl string

	// DBMaxConns caps the pgxpool connection pool size.
	// Default: 8
	DBMaxConns int

	// JWTSecret is the HMAC-SHA256 signing key for JWT tokens.
	// Must be at least 32 bytes when DevMode is false.
	JWTSecret string

	// JWTIssuer is the "iss" claim value used when minting tokens.
	// Default: "securelab"
	JWTIssuer string

	// TokenTTL controls how long minted JWT tokens remain valid.
	// Default: 12h
	TokenTTL time.Duration

	// CitadelAPIURL is the base URL of the Citadel event-broker API.
	CitadelAPIURL string

	// CitadelHMACSecrets is the ordered list of shared HMAC secrets used to
	// verify Citadel webhook payloads. Required when CitadelDryRun is false.
	CitadelHMACSecrets []string

	// CitadelDryRun disables live Citadel event dispatch; events are logged
	// locally instead. Default: true.
	CitadelDryRun bool

	// Node is the logical node identifier included in emitted events.
	// Default: "securelab-0"
	Node string

	// OutboxTick is how often the transactional outbox worker flushes pending
	// events to Citadel. Default: 10s
	OutboxTick time.Duration

	// MaxConcurrentScenarios limits how many scenario runs can execute in
	// parallel. Default: 3
	MaxConcurrentScenarios int

	// ScenarioTimeout is the default execution deadline for a scenario run
	// when the scenario YAML does not specify its own timeout. Default: 5m
	ScenarioTimeout time.Duration

	// SinauthURL is the base URL of the sinauth OIDC issuer used for RS256 SSO
	// token verification. Set via SECURELAB_SINAUTH_URL. When non-empty, Bearer
	// tokens with alg=RS256 are verified via the sinauth SDK; HS256 tokens
	// continue to use the existing golang-jwt/HMAC path.
	// Default: "http://localhost:8100"
	SinauthURL string
}
