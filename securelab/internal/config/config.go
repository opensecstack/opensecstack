// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const envPrefix = "SECURELAB_"

// FromEnv constructs a Config by reading environment variables prefixed with
// SECURELAB_. All fields have sensible defaults; callers must invoke Validate
// before using the returned config in production paths.
func FromEnv() (*Config, error) {
	cfg := &Config{
		HTTPAddr:               ":8085",
		DBMaxConns:             8,
		JWTIssuer:              "securelab",
		TokenTTL:               12 * time.Hour,
		CitadelDryRun:          true,
		Node:                   "securelab-0",
		OutboxTick:             10 * time.Second,
		MaxConcurrentScenarios: 3,
		ScenarioTimeout:        5 * time.Minute,
		SinauthURL:             "http://localhost:8100",
	}

	if v := env("HTTP_ADDR"); v != "" {
		cfg.HTTPAddr = v
	}
	if v := env("DEV_MODE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("config: SECURELAB_DEV_MODE must be a boolean: %w", err)
		}
		cfg.DevMode = b
	}
	if v := env("DB_URL"); v != "" {
		cfg.DBUrl = v
	}
	if v := env("DB_MAX_CONNS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("config: SECURELAB_DB_MAX_CONNS must be a positive integer: %w", err)
		}
		cfg.DBMaxConns = n
	}
	if v := env("JWT_SECRET"); v != "" {
		cfg.JWTSecret = v
	}
	if v := env("JWT_ISSUER"); v != "" {
		cfg.JWTIssuer = v
	}
	if v := env("TOKEN_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("config: SECURELAB_TOKEN_TTL must be a Go duration: %w", err)
		}
		cfg.TokenTTL = d
	}
	if v := env("CITADEL_API_URL"); v != "" {
		cfg.CitadelAPIURL = v
	}
	if v := env("CITADEL_HMAC_SECRETS"); v != "" {
		parts := strings.Split(v, ",")
		secrets := make([]string, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				secrets = append(secrets, s)
			}
		}
		cfg.CitadelHMACSecrets = secrets
	}
	if v := env("CITADEL_DRY_RUN"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("config: SECURELAB_CITADEL_DRY_RUN must be a boolean: %w", err)
		}
		cfg.CitadelDryRun = b
	}
	if v := env("NODE"); v != "" {
		cfg.Node = v
	}
	if v := env("OUTBOX_TICK"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("config: SECURELAB_OUTBOX_TICK must be a Go duration: %w", err)
		}
		cfg.OutboxTick = d
	}
	if v := env("MAX_CONCURRENT_SCENARIOS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("config: SECURELAB_MAX_CONCURRENT_SCENARIOS must be a positive integer: %w", err)
		}
		cfg.MaxConcurrentScenarios = n
	}
	if v := env("SCENARIO_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("config: SECURELAB_SCENARIO_TIMEOUT must be a Go duration: %w", err)
		}
		cfg.ScenarioTimeout = d
	}
	if v := env("SINAUTH_URL"); v != "" {
		cfg.SinauthURL = v
	}

	return cfg, nil
}

// Validate returns an error if the config is unusable for production use.
// When DevMode is true the stricter checks are skipped, matching the pattern
// used across the opensecstack monorepo.
func (c *Config) Validate() error {
	var errs []error

	if c.DBUrl == "" {
		errs = append(errs, errors.New("config: SECURELAB_DB_URL is required"))
	}

	if !c.DevMode {
		if len(c.JWTSecret) < 32 {
			errs = append(errs, errors.New("config: SECURELAB_JWT_SECRET must be at least 32 bytes"))
		}
		if !c.CitadelDryRun && len(c.CitadelHMACSecrets) == 0 {
			errs = append(errs, errors.New("config: SECURELAB_CITADEL_HMAC_SECRETS is required when CITADEL_DRY_RUN=false"))
		}
	}

	if len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		return errors.New(strings.Join(msgs, "; "))
	}

	return nil
}

// env returns the value of the environment variable named by the SECURELAB_
// prefix joined with key.
func env(key string) string {
	return os.Getenv(envPrefix + key)
}
