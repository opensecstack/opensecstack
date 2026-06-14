// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

// Package api contains OWASP API Security Top 10 attack simulations.
// All attacks target ONLY explicitly configured, isolated Docker environments.
package api

import (
	"errors"
	"strings"
	"time"
)

// AttackResult holds the outcome of a single attack simulation run.
type AttackResult struct {
	Technique string
	Success   bool
	Evidence  []string
	Duration  time.Duration
}

// blockedTargetPatterns holds substrings that indicate a production target.
var blockedTargetPatterns = []string{
	".prod",
	"-prod",
	"_prod",
	"production",
	".live",
	"-live",
}

// checkTarget returns an error when the target URL resembles a production system.
func checkTarget(targetURL string) error {
	lower := strings.ToLower(targetURL)
	for _, pattern := range blockedTargetPatterns {
		if strings.Contains(lower, pattern) {
			return errors.New("safety: target URL matches production blocklist pattern (" + pattern + "); refusing to run attack against non-isolated environment")
		}
	}
	return nil
}
