// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/opensecstack/securelab/internal/db"
)

// ValidStepKinds is the exhaustive set of recognised attack primitive kinds.
var ValidStepKinds = map[string]struct{}{
	"bola":              {},
	"auth_bypass":       {},
	"mass_assignment":   {},
	"rate_limit_bypass": {},
	"ssrf":              {},
	"misconfig":         {},
	"syn_flood":         {},
	"udp_flood":         {},
	"http_flood":        {},
	"slowloris":         {},
	"port_scan":         {},
	"endpoint_enum":     {},
	"version_detect":    {},
	"data_exfil":        {},
	"dns_tunnel":        {},
}

// productionBlocklist is the set of hostname patterns that must never be
// targeted by SecureLab scenarios. Patterns beginning with "*." are suffix
// checks; patterns ending with ".*" are prefix checks.
var productionBlocklist = []string{
	"*.prod",
	"*.production",
	"production.*",
}

// Validate performs semantic validation of a ScenarioSpec against the
// supplied target Environment. It returns a single combined error describing
// all validation failures, or nil when the spec is safe to execute.
func Validate(spec *ScenarioSpec, env *db.Environment) error {
	if spec == nil {
		return errors.New("scenarios: spec must not be nil")
	}

	var errs []string

	if strings.TrimSpace(spec.Name) == "" {
		errs = append(errs, "name must not be empty")
	}

	if len(spec.Steps) == 0 {
		errs = append(errs, "steps must not be empty")
	}

	for i, step := range spec.Steps {
		if _, ok := ValidStepKinds[step.Kind]; !ok {
			errs = append(errs, fmt.Sprintf("step[%d]: unknown kind %q", i, step.Kind))
		}
	}

	if env != nil && env.TargetURL != "" {
		if err := checkNotProduction(env.TargetURL); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("scenarios: validation failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

// checkNotProduction returns an error if targetURL matches any entry in the
// production blocklist.
func checkNotProduction(targetURL string) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		// If we cannot parse the URL we block it to be safe.
		return fmt.Errorf("target URL %q is not parsable and has been blocked", targetURL)
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return nil
	}

	for _, pattern := range productionBlocklist {
		if matched, desc := matchHostnamePattern(hostname, pattern); matched {
			return fmt.Errorf(
				"target URL %q matches production blocklist pattern %q (%s); refusing to run",
				targetURL, pattern, desc,
			)
		}
	}
	return nil
}

// matchHostnamePattern checks whether hostname matches the blocklist pattern.
// Patterns of the form "*.suffix" match any hostname ending with ".suffix".
// Patterns of the form "prefix.*" match any hostname starting with "prefix.".
func matchHostnamePattern(hostname, pattern string) (bool, string) {
	switch {
	case strings.HasPrefix(pattern, "*."):
		suffix := strings.TrimPrefix(pattern, "*")
		if strings.HasSuffix(hostname, suffix) || hostname == strings.TrimPrefix(suffix, ".") {
			return true, "suffix match"
		}
	case strings.HasSuffix(pattern, ".*"):
		prefix := strings.TrimSuffix(pattern, ".*") + "."
		if strings.HasPrefix(hostname, prefix) {
			return true, "prefix match"
		}
	default:
		if hostname == pattern {
			return true, "exact match"
		}
	}
	return false, ""
}
