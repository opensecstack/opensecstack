package modules

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/opensecstack/apiguard/internal/domain"
)

// InventoryModule implements OWASP API9:2023 — Improper Inventory Management.
type InventoryModule struct{}

func (m *InventoryModule) ID() string   { return "a9_inventory" }
func (m *InventoryModule) Name() string { return "Improper Inventory Management" }

// Run executes inventory management test cases from the provided suite against the target.
func (m *InventoryModule) Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	visited := make(map[string]bool)

	for _, tc := range suite.Cases {
		switch tc.Category {
		case "inventory_api_version", "inventory_deprecated_header", "inventory_debug_endpoint":
		default:
			continue
		}

		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		key := tc.Category + "|" + tc.Method + "|" + tc.Path
		if visited[key] {
			continue
		}
		visited[key] = true

		switch tc.Category {
		case "inventory_api_version":
			f, err := m.runAPIVersion(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)

		case "inventory_deprecated_header":
			f, err := m.runDeprecatedHeader(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)

		case "inventory_debug_endpoint":
			f, err := m.runDebugEndpoints(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

// versionPattern matches API version segments such as /v1, /v2, /api/v3.
var versionPattern = regexp.MustCompile(`(?i)(/api)?/v(\d+)(/|$)`)

// candidateVersionPrefixes returns a list of version-prefixed paths to probe adjacent to the current path.
func candidateVersionPrefixes() []string {
	return []string{
		"/v1", "/v2", "/v3",
		"/api/v1", "/api/v2", "/api/v3",
	}
}

// runAPIVersion checks whether stale or unexpected API version paths are accessible.
func (m *InventoryModule) runAPIVersion(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	// Determine the current version from the path so we can exclude it.
	currentVersionMatch := versionPattern.FindString(tc.Path)

	// Strip any existing version prefix to get the resource portion of the path.
	resourcePath := versionPattern.ReplaceAllString(tc.Path, "/")
	resourcePath = "/" + strings.TrimLeft(resourcePath, "/")

	for _, prefix := range candidateVersionPrefixes() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Skip the version already in the test case path.
		if currentVersionMatch != "" && strings.HasSuffix(strings.ToLower(prefix), strings.ToLower(strings.TrimSuffix(currentVersionMatch, "/"))) {
			continue
		}

		probeURL := strings.TrimRight(target, "/") + prefix + resourcePath
		resp, err := doRequest(ctx, exec, http.MethodGet, probeURL, tc.Headers, nil, auth)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			findings = append(findings, domain.Finding{
				OWASPId:        "API9:2023",
				ModuleID:       m.ID(),
				Title:          "Old API Version Accessible",
				Description:    fmt.Sprintf("An older or unexpected API version path %q returned HTTP 200. Stale API versions may lack current security controls and expose deprecated functionality.", prefix+resourcePath),
				Severity:       domain.SeverityMedium,
				CVSSScore:      5.3,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
				Status:         domain.FindingStatusOpen,
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("GET %s", probeURL),
					Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
					Detail: map[string]interface{}{
						"probed_path":    prefix + resourcePath,
						"original_path":  tc.Path,
					},
				},
				Remediation: "Decommission old API versions or protect them with the same authentication and authorisation controls as current versions. Maintain an up-to-date API inventory and enforce version sunset policies.",
			})
		}
	}

	return findings, nil
}

// runDeprecatedHeader checks for Deprecation or Sunset headers that expose API lifecycle information.
func (m *InventoryModule) runDeprecatedHeader(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	url := strings.TrimRight(target, "/") + tc.Path
	resp, err := doRequest(ctx, exec, http.MethodGet, url, tc.Headers, nil, auth)
	if err != nil {
		return nil, fmt.Errorf("deprecated header request failed: %w", err)
	}

	for _, headerName := range []string{"Deprecation", "Sunset"} {
		val := resp.Headers.Get(headerName)
		if val != "" {
			findings = append(findings, domain.Finding{
				OWASPId:        "API9:2023",
				ModuleID:       m.ID(),
				Title:          fmt.Sprintf("API Lifecycle Header %q Exposed", headerName),
				Description:    fmt.Sprintf("Endpoint %s %s returns a %s header with value %q. This reveals API lifecycle information that attackers can use to target soon-to-be-deprecated endpoints.", tc.Method, tc.Path, headerName, val),
				Severity:       domain.SeverityInfo,
				CVSSScore:      2.0,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
				Status:         domain.FindingStatusOpen,
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("GET %s", url),
					Response: fmt.Sprintf("HTTP %d (%s: %s)", resp.StatusCode, headerName, val),
					Detail: map[string]interface{}{
						"header_name":  headerName,
						"header_value": val,
					},
				},
				Remediation: "Review whether exposing API lifecycle headers externally is intentional. Ensure that deprecated endpoints are properly secured or removed before their sunset date.",
			})
		}
	}

	return findings, nil
}

// debugEndpointPaths are common debug, monitoring, and documentation paths to probe.
var debugEndpointPaths = []string{
	"/actuator",
	"/actuator/health",
	"/actuator/env",
	"/_debug",
	"/debug",
	"/status",
	"/info",
	"/metrics",
	"/.well-known/",
	"/swagger-ui.html",
	"/api-docs",
	"/graphql",
}

// runDebugEndpoints probes well-known debug and monitoring paths for unintended exposure.
func (m *InventoryModule) runDebugEndpoints(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, _ *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	for _, path := range debugEndpointPaths {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Send unauthenticated GET to detect endpoints that should not be publicly accessible.
		probeURL := strings.TrimRight(target, "/") + path
		resp, err := doRequest(ctx, exec, http.MethodGet, probeURL, nil, nil, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			findings = append(findings, domain.Finding{
				OWASPId:        "API9:2023",
				ModuleID:       m.ID(),
				Title:          "Debug or Monitoring Endpoint Exposed",
				Description:    fmt.Sprintf("The path %q returned HTTP 200 without authentication. Exposed debug and monitoring endpoints can leak sensitive configuration, environment variables, and internal system state.", path),
				Severity:       domain.SeverityHigh,
				CVSSScore:      7.5,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Status:         domain.FindingStatusOpen,
				EndpointPath:   path,
				EndpointMethod: http.MethodGet,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("GET %s", probeURL),
					Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
					Detail: map[string]interface{}{
						"probed_path": path,
						"target":      target,
					},
				},
				Remediation: "Restrict access to debug and monitoring endpoints at the network or application layer. These paths should never be accessible from untrusted networks without authentication.",
			})
		}
	}

	return findings, nil
}
