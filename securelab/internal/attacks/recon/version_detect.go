// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package recon

// Server version detection.
//
// Extracts version information from HTTP response headers and well-known
// version disclosure endpoints. Records any disclosed software versions.
//
// Safety guarantee: target must be loopback or RFC 1918.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VersionInfo holds one detected version disclosure.
type VersionInfo struct {
	Source  string // header name or endpoint path
	Name    string // software name if parseable
	Version string // version string
	Raw     string // raw header/body value
}

// VersionDetectResult extends AttackResult with detected versions.
type VersionDetectResult struct {
	AttackResult
	Versions []VersionInfo
}

// versionHeaders are HTTP headers commonly used to disclose server technology.
var versionHeaders = []string{
	"Server",
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
	"X-Generator",
	"X-Drupal-Cache",
	"X-WordPress-Loaded",
	"Via",
	"X-Served-By",
	"X-Runtime",
	"X-Version",
}

// versionEndpoints are paths that many frameworks expose version/build info on.
var versionEndpoints = []string{
	"/version",
	"/api/version",
	"/info",
	"/actuator/info",
	"/actuator/health",
	"/health",
	"/.well-known/security.txt",
	"/api/v1/version",
	"/build-info",
}

// VersionDetector probes for server version disclosure.
type VersionDetector struct {
	client *http.Client
}

// NewVersionDetector returns a ready VersionDetector.
func NewVersionDetector() *VersionDetector {
	return &VersionDetector{
		client: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Run detects version disclosures on targetURL.
//
// Recognised params keys:
//   - "jwt"  string — optional Bearer token
func (v *VersionDetector) Run(ctx context.Context, targetURL string, params map[string]any) (*VersionDetectResult, error) {
	if err := checkTarget(ctx, extractHost(targetURL)); err != nil {
		return nil, err
	}

	jwt, _ := params["jwt"].(string)
	base := strings.TrimRight(targetURL, "/")

	start := time.Now()
	result := &VersionDetectResult{
		AttackResult: AttackResult{Technique: "VersionDetect"},
	}

	// 1. Probe the base URL and extract version headers.
	if resp, err := v.get(ctx, base+"/", jwt); err == nil {
		for _, hdr := range versionHeaders {
			val := resp.Header.Get(hdr)
			if val != "" {
				info := VersionInfo{
					Source: "header:" + hdr,
					Raw:    val,
				}
				parseSoftwareVersion(val, &info)
				result.Versions = append(result.Versions, info)
				result.Evidence = append(result.Evidence,
					fmt.Sprintf("VersionDetect[header]: %s: %q", hdr, val))
			}
		}
		resp.Body.Close()
	}

	// 2. Probe well-known version endpoints.
	for _, ep := range versionEndpoints {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		url := base + ep
		resp, err := v.get(ctx, url, jwt)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		// Also check response headers from this endpoint.
		for _, hdr := range versionHeaders {
			if val := resp.Header.Get(hdr); val != "" {
				info := VersionInfo{Source: "header:" + hdr + "@" + ep, Raw: val}
				parseSoftwareVersion(val, &info)
				result.Versions = append(result.Versions, info)
				result.Evidence = append(result.Evidence,
					fmt.Sprintf("VersionDetect[header@%s]: %s: %q", ep, hdr, val))
			}
		}

		// Try to parse JSON body for version fields.
		bodyStr := string(body)
		if strings.Contains(resp.Header.Get("Content-Type"), "json") {
			if versions := extractJSONVersions(body, ep); len(versions) > 0 {
				result.Versions = append(result.Versions, versions...)
				for _, vi := range versions {
					result.Evidence = append(result.Evidence,
						fmt.Sprintf("VersionDetect[json@%s]: %q = %q", ep, vi.Name, vi.Version))
				}
			}
		} else if containsVersionSignal(bodyStr) {
			info := VersionInfo{Source: "body:" + ep, Raw: truncate(bodyStr, 200)}
			result.Versions = append(result.Versions, info)
			result.Evidence = append(result.Evidence,
				fmt.Sprintf("VersionDetect[body@%s]: version disclosure in response (snippet=%q)", ep, truncate(bodyStr, 100)))
		}
	}

	result.Duration = time.Since(start)
	if len(result.Versions) > 0 {
		result.Success = true
	}
	return result, nil
}

func (v *VersionDetector) get(ctx context.Context, url, jwt string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	return v.client.Do(req)
}

// parseSoftwareVersion attempts to split "nginx/1.25.3" into Name+Version.
func parseSoftwareVersion(raw string, info *VersionInfo) {
	if idx := strings.IndexByte(raw, '/'); idx >= 0 {
		info.Name = raw[:idx]
		info.Version = raw[idx+1:]
		return
	}
	if idx := strings.IndexByte(raw, ' '); idx >= 0 {
		info.Name = raw[:idx]
		info.Version = strings.TrimSpace(raw[idx+1:])
		return
	}
	info.Name = raw
}

// extractJSONVersions looks for common version-related keys in a JSON object.
func extractJSONVersions(body []byte, source string) []VersionInfo {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	keys := []string{"version", "buildVersion", "build", "commit", "revision", "tag", "appVersion", "apiVersion"}
	var out []VersionInfo
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, VersionInfo{Source: "json:" + source, Name: k, Version: s, Raw: s})
			}
		}
	}
	return out
}

// containsVersionSignal returns true when the body text looks like it contains
// version information.
func containsVersionSignal(body string) bool {
	signals := []string{"version", "release", "build", "commit", "revision"}
	lower := strings.ToLower(body)
	for _, s := range signals {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// truncate limits s to n runes.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
