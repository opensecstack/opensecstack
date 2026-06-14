// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package recon

// Wordlist-based endpoint enumeration.
//
// Probes a built-in wordlist of common API and admin paths against the target,
// recording discovered endpoints with their HTTP status codes.
//
// Safety guarantee: target must be loopback or RFC 1918.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DiscoveredEndpoint holds one enumerated path with its response code.
type DiscoveredEndpoint struct {
	Path       string
	StatusCode int
	Size       int64
}

// EndpointEnumResult extends AttackResult with discovered endpoints.
type EndpointEnumResult struct {
	AttackResult
	Endpoints []DiscoveredEndpoint
}

// builtinWordlist contains common API, admin, and framework paths.
var builtinWordlist = []string{
	"/api", "/api/v1", "/api/v2", "/api/v3",
	"/admin", "/admin/", "/administrator",
	"/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
	"/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
	"/health", "/healthz", "/health/live", "/health/ready",
	"/metrics", "/prometheus",
	"/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
	"/debug", "/debug/vars", "/debug/pprof",
	"/status", "/info", "/version",
	"/.env", "/.git/HEAD", "/.git/config",
	"/config", "/config.json", "/config.yaml", "/settings",
	"/login", "/logout", "/register", "/signup",
	"/users", "/user", "/account", "/accounts",
	"/dashboard", "/panel", "/console",
	"/graphql", "/graphiql", "/playground",
	"/wp-admin", "/wp-login.php", "/xmlrpc.php",
	"/phpmyadmin", "/phpinfo.php",
	"/backup", "/backup.zip", "/db.sql",
	"/robots.txt", "/sitemap.xml", "/crossdomain.xml",
	"/.well-known/security.txt",
}

// EndpointEnumerator probes wordlist paths against a target URL.
type EndpointEnumerator struct {
	client *http.Client
}

// NewEndpointEnumerator returns a ready EndpointEnumerator.
func NewEndpointEnumerator() *EndpointEnumerator {
	return &EndpointEnumerator{
		client: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // do not follow redirects
			},
		},
	}
}

// Run enumerates endpoints on targetURL.
//
// Recognised params keys:
//   - "extra_paths"   []string — additional paths to probe beyond the built-in list
//   - "concurrency"   int      — parallel probes (default 10, max 50)
//   - "jwt"           string   — optional Bearer token
func (e *EndpointEnumerator) Run(ctx context.Context, targetURL string, params map[string]any) (*EndpointEnumResult, error) {
	if err := checkTarget(extractHost(targetURL)); err != nil {
		return nil, err
	}

	concurrency := intParam(params, "concurrency", 10, 50)
	jwt, _ := params["jwt"].(string)

	var extraPaths []string
	if ep, ok := params["extra_paths"]; ok {
		switch v := ep.(type) {
		case []string:
			extraPaths = v
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					extraPaths = append(extraPaths, s)
				}
			}
		}
	}

	wordlist := append(builtinWordlist, extraPaths...)
	base := strings.TrimRight(targetURL, "/")

	start := time.Now()
	result := &EndpointEnumResult{
		AttackResult: AttackResult{Technique: "EndpointEnum"},
	}

	type probeResult struct {
		path   string
		code   int
		size   int64
		err    error
	}

	paths := make(chan string, concurrency)
	results := make(chan probeResult, len(wordlist))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range paths {
				select {
				case <-ctx.Done():
					return
				default:
				}

				url := base + path
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
				if err != nil {
					results <- probeResult{path: path, err: err}
					continue
				}
				if jwt != "" {
					req.Header.Set("Authorization", "Bearer "+jwt)
				}
				req.Header.Set("Accept", "*/*")

				resp, err := e.client.Do(req)
				if err != nil {
					results <- probeResult{path: path, err: err}
					continue
				}
				size := resp.ContentLength
				resp.Body.Close()
				results <- probeResult{path: path, code: resp.StatusCode, size: size}
			}
		}()
	}

	go func() {
		for _, p := range wordlist {
			select {
			case <-ctx.Done():
				break
			case paths <- p:
			}
		}
		close(paths)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.err != nil {
			continue
		}
		// Record anything that returned a non-404 non-error response.
		if r.code != http.StatusNotFound && r.code != 0 {
			ep := DiscoveredEndpoint{Path: r.path, StatusCode: r.code, Size: r.size}
			result.Endpoints = append(result.Endpoints, ep)
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("EndpointEnum: %s%s HTTP %d (size=%d)", base, r.path, r.code, r.size))
		}
	}

	result.Duration = time.Since(start)
	if len(result.Endpoints) > 0 {
		result.Success = true
	}
	return result, ctx.Err()
}

// extractHost pulls just the host portion from a URL string for safety checks.
func extractHost(rawURL string) string {
	// Fast path: strip scheme.
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(rawURL, prefix) {
			rest := rawURL[len(prefix):]
			if idx := strings.IndexAny(rest, "/:?#"); idx >= 0 {
				return rest[:idx]
			}
			return rest
		}
	}
	return rawURL
}
