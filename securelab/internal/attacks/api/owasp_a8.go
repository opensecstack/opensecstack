// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

// OWASP API8:2023 — Security Misconfiguration
//
// Checks for:
//   - Exposed debug/actuator/metrics endpoints without authentication.
//   - Default or well-known credentials accepted.
//   - Verbose error messages leaking stack traces or internal paths.
//   - Missing or misconfigured security headers.
//
// Safety guarantee: production blocklist check runs before any network I/O.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MisconfigAttack simulates OWASP API8 — Security Misconfiguration.
type MisconfigAttack struct {
	client *http.Client
}

// NewMisconfigAttack returns a ready MisconfigAttack.
func NewMisconfigAttack() *MisconfigAttack {
	return &MisconfigAttack{client: &http.Client{Timeout: 8 * time.Second}}
}

// debugEndpoints are well-known paths that should never be publicly accessible.
var debugEndpoints = []string{
	"/debug", "/debug/vars", "/debug/pprof", "/debug/pprof/heap",
	"/actuator", "/actuator/env", "/actuator/beans", "/actuator/health",
	"/actuator/info", "/actuator/mappings", "/actuator/httptrace",
	"/metrics", "/prometheus", "/_ah/health",
	"/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
	"/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
	"/.env", "/config", "/info", "/status",
	"/phpinfo.php", "/__admin", "/console",
}

// defaultCredentials are common default login pairs.
var defaultCredentials = []struct{ user, pass string }{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "123456"},
	{"root", "root"},
	{"root", ""},
	{"test", "test"},
	{"guest", "guest"},
	{"user", "user"},
}

// requiredSecurityHeaders lists headers that should be present on responses.
var requiredSecurityHeaders = []string{
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Content-Security-Policy",
	"Strict-Transport-Security",
	"X-XSS-Protection",
	"Referrer-Policy",
}

// Run executes all misconfiguration checks against targetURL.
//
// Recognised params keys:
//   - "login_endpoint"  string — path for default credential probing (default "/api/login")
//   - "jwt"             string — optional token for authenticated checks
func (a *MisconfigAttack) Run(ctx context.Context, targetURL string, params map[string]any) (*AttackResult, error) {
	if err := checkTarget(targetURL); err != nil {
		return nil, err
	}

	start := time.Now()
	result := &AttackResult{Technique: "Misconfiguration"}
	base := strings.TrimRight(targetURL, "/")

	// 1. Exposed debug/framework endpoints.
	for _, ep := range debugEndpoints {
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
		resp, err := a.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			result.Success = true
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("Misconfig[debug-endpoint]: GET %s returned HTTP 200 (snippet=%q)",
					url, truncate(string(body), 150)))
		}
	}

	// 2. Default credentials.
	loginEndpoint, _ := params["login_endpoint"].(string)
	if loginEndpoint == "" {
		loginEndpoint = "/api/login"
	}
	loginURL := base + loginEndpoint

	for _, cred := range defaultCredentials {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		payload, _ := json.Marshal(map[string]string{
			"username": cred.user,
			"password": cred.pass,
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := a.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			result.Success = true
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("Misconfig[default-creds]: POST %s with %s:%s — HTTP %d (snippet=%q)",
					loginURL, cred.user, cred.pass, resp.StatusCode, truncate(string(body), 100)))
		}
	}

	// 3. Verbose errors — send a malformed request.
	{
		url := base + "/api/users/not-a-valid-id-99999"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err == nil {
			resp, err := a.client.Do(req)
			if err == nil {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				if verboseError(string(body)) {
					result.Success = true
					result.Evidence = append(result.Evidence,
						fmt.Sprintf("Misconfig[verbose-error]: GET %s — response leaks stack trace or internal paths (snippet=%q)",
							url, truncate(string(body), 200)))
				}
			}
		}
	}

	// 4. Missing security headers on base URL.
	{
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
		if err == nil {
			resp, err := a.client.Do(req)
			if err == nil {
				resp.Body.Close()
				for _, hdr := range requiredSecurityHeaders {
					if resp.Header.Get(hdr) == "" {
						result.Success = true
						result.Evidence = append(result.Evidence,
							fmt.Sprintf("Misconfig[missing-header]: response from %s is missing security header %q",
								base+"/", hdr))
					}
				}
			}
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// verboseError returns true when the body looks like a stack trace or exposes
// internal implementation details.
func verboseError(body string) bool {
	indicators := []string{
		"at ", "stack trace", "traceback", "exception",
		"NullPointerException", "SQLException", "ORA-", "SQLSTATE",
		"/home/", "/var/www", "/usr/local", "src/main/",
		"goroutine ", "panic:", "runtime error",
	}
	lower := strings.ToLower(body)
	for _, ind := range indicators {
		if strings.Contains(lower, strings.ToLower(ind)) {
			return true
		}
	}
	return false
}
