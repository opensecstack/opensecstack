package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/opensecstack/apiguard/internal/cvss"
	"github.com/opensecstack/apiguard/internal/domain"
)

// MassAssignmentModule detects OWASP API3:2023 Broken Object Property Level Authorization
// (mass assignment) vulnerabilities by injecting extra or read-only fields into API requests.
type MassAssignmentModule struct{}

// ID returns the module identifier.
func (m *MassAssignmentModule) ID() string { return "a3_mass_assignment" }

// Name returns the human-readable module name.
func (m *MassAssignmentModule) Name() string {
	return "Broken Object Property Level Authorization"
}

// Run executes all mass assignment test cases and returns findings.
func (m *MassAssignmentModule) Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	for _, tc := range suite.Cases {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		switch tc.Category {
		case "mass_assign_extra_fields":
			f, err := m.executeExtraFields(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		case "mass_assign_readonly":
			f, err := m.executeReadOnly(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

// executeExtraFields tests whether the API accepts additional fields not in the schema.
func (m *MassAssignmentModule) executeExtraFields(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	method := tc.Method
	path := tc.Path
	url := strings.TrimRight(target, "/") + path

	// Baseline: send the original request body.
	baselineResp, err := doRequest(ctx, exec, method, url, tc.Headers, tc.Body, auth)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	// Build an attack body by injecting extra fields.
	attackBody, err := injectExtraFields(tc.Body)
	if err != nil || attackBody == nil {
		return nil, nil
	}

	// Send attack request with extra fields.
	attackResp, err := doRequest(ctx, exec, method, url, tc.Headers, attackBody, auth)
	if err != nil {
		return nil, fmt.Errorf("attack request failed: %w", err)
	}

	// If the server properly rejects unknown fields with a validation error, no finding.
	if attackResp.StatusCode == 400 || attackResp.StatusCode == 422 {
		return nil, nil
	}

	var findings []domain.Finding

	if attackResp.StatusCode >= 200 && attackResp.StatusCode < 300 {
		injectedFields := diffBodies(tc.Body, attackBody)
		reflectedFields := findReflectedFieldsInBody(attackResp.Body, injectedFields)

		if len(reflectedFields) > 0 {
			for _, fieldName := range reflectedFields {
				findings = append(findings, domain.Finding{
					OWASPId:        "API3:2023",
					ModuleID:       "a3_mass_assignment",
					Title:          "Mass Assignment Vulnerability on " + method + " " + path,
					Description:    "The endpoint accepts and processes additional fields that were not part of the original schema. Injected field: " + fieldName,
					Severity:       domain.SeverityHigh,
					CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"),
					CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
					EndpointPath:   path,
					EndpointMethod: method,
					Evidence: domain.Evidence{
						Request:  fmt.Sprintf("%s %s (injected: %s)", method, url, fieldName),
						Response: fmt.Sprintf("HTTP %d", attackResp.StatusCode),
						Detail: map[string]interface{}{
							"injected_field":        fieldName,
							"all_injected_fields":   formatInjectedFields(injectedFields),
							"baseline_status":       baselineResp.StatusCode,
							"attack_status":         attackResp.StatusCode,
							"field_reflected":       true,
							"category":              "mass_assign_extra_fields",
						},
					},
					Remediation: "Implement allowlist-based input validation. Only accept fields explicitly defined in the API schema. Reject or ignore unknown properties.",
					Status:      domain.FindingStatusOpen,
				})
			}
		} else {
			changedFields := diffResponseBodies(baselineResp.Body, attackResp.Body)
			if len(changedFields) > 0 {
				findings = append(findings, domain.Finding{
					OWASPId:        "API3:2023",
					ModuleID:       "a3_mass_assignment",
					Title:          "Extra Fields Accepted Without Validation on " + method + " " + path,
					Description:    "The endpoint accepts requests containing additional fields not defined in the API schema without rejecting them.",
					Severity:       domain.SeverityMedium,
					CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N"),
					CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
					EndpointPath:   path,
					EndpointMethod: method,
					Evidence: domain.Evidence{
						Request:  fmt.Sprintf("%s %s (with extra fields)", method, url),
						Response: fmt.Sprintf("HTTP %d", attackResp.StatusCode),
						Detail: map[string]interface{}{
							"baseline_status": baselineResp.StatusCode,
							"attack_status":   attackResp.StatusCode,
							"changed_fields":  changedFields,
							"category":        "mass_assign_extra_fields",
						},
					},
					Remediation: "Configure strict input validation to reject requests containing unexpected fields (additionalProperties: false in OpenAPI).",
					Status:      domain.FindingStatusOpen,
				})
			}
		}
	}

	return findings, nil
}

// executeReadOnly tests whether the API allows modification of read-only fields.
func (m *MassAssignmentModule) executeReadOnly(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	method := tc.Method
	path := tc.Path
	url := strings.TrimRight(target, "/") + path

	attackResp, err := doRequest(ctx, exec, method, url, tc.Headers, tc.Body, auth)
	if err != nil {
		return nil, fmt.Errorf("attack request failed: %w", err)
	}

	// If the server rejects with a validation error, it is properly protected.
	if attackResp.StatusCode == 400 || attackResp.StatusCode == 422 {
		return nil, nil
	}

	var findings []domain.Finding

	if attackResp.StatusCode >= 200 && attackResp.StatusCode < 300 {
		readOnlyFields := extractReadOnlyFieldsFromBody(tc.Body)
		reflectedFields := findReflectedFieldsInBody(attackResp.Body, readOnlyFields)

		for _, fieldName := range reflectedFields {
			findings = append(findings, domain.Finding{
				OWASPId:        "API3:2023",
				ModuleID:       "a3_mass_assignment",
				Title:          "Read-Only Field Overwrite on " + method + " " + path,
				Description:    "The endpoint allows modification of read-only field: " + fieldName,
				Severity:       domain.SeverityHigh,
				CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"),
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
				EndpointPath:   path,
				EndpointMethod: method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("%s %s (readonly field: %s)", method, url, fieldName),
					Response: fmt.Sprintf("HTTP %d", attackResp.StatusCode),
					Detail: map[string]interface{}{
						"readonly_field":  fieldName,
						"injected_value":  readOnlyFields[fieldName],
						"field_reflected": true,
						"category":        "mass_assign_readonly",
					},
				},
				Remediation: "Enforce read-only constraints on fields like id, created_at, updated_at at the API layer, not just the database layer.",
				Status:      domain.FindingStatusOpen,
			})
		}
	}

	return findings, nil
}

// injectExtraFields adds common mass-assignment probe fields to a JSON body.
func injectExtraFields(body []byte) ([]byte, error) {
	if len(body) == 0 {
		body = []byte(`{}`)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	parsed["admin"] = true
	parsed["role"] = "admin"
	parsed["is_admin"] = true
	return json.Marshal(parsed)
}

// diffBodies returns a map of fields present in the attack body but not in the baseline.
func diffBodies(baseline, attack []byte) map[string]interface{} {
	var baseFields, attackFields map[string]interface{}
	if json.Unmarshal(baseline, &baseFields) != nil {
		baseFields = map[string]interface{}{}
	}
	if json.Unmarshal(attack, &attackFields) != nil {
		return nil
	}
	extra := make(map[string]interface{})
	for key, val := range attackFields {
		if _, exists := baseFields[key]; !exists {
			extra[key] = val
		}
	}
	return extra
}

// diffResponseBodies finds fields that changed between baseline and attack response bodies.
func diffResponseBodies(baseline, attack []byte) []string {
	var baseFields, attackFields map[string]interface{}
	if json.Unmarshal(baseline, &baseFields) != nil || json.Unmarshal(attack, &attackFields) != nil {
		return nil
	}
	var changed []string
	for key, attackVal := range attackFields {
		baseVal, exists := baseFields[key]
		if !exists {
			changed = append(changed, key)
			continue
		}
		b1, _ := json.Marshal(baseVal)
		b2, _ := json.Marshal(attackVal)
		if !bytes.Equal(b1, b2) {
			changed = append(changed, key)
		}
	}
	return changed
}

// findReflectedFieldsInBody checks which of the injected fields appear in the response body.
func findReflectedFieldsInBody(responseBody []byte, injectedFields map[string]interface{}) []string {
	var resp map[string]interface{}
	if json.Unmarshal(responseBody, &resp) != nil {
		return nil
	}
	// Also unwrap a common "data" envelope.
	if data, ok := resp["data"]; ok {
		if dataMap, ok := data.(map[string]interface{}); ok {
			for k, v := range dataMap {
				resp[k] = v
			}
		}
	}
	var reflected []string
	for fieldName, expectedValue := range injectedFields {
		actual, exists := resp[fieldName]
		if !exists {
			continue
		}
		expJSON, _ := json.Marshal(expectedValue)
		actJSON, _ := json.Marshal(actual)
		if string(expJSON) == string(actJSON) {
			reflected = append(reflected, fieldName)
		}
	}
	return reflected
}

// extractReadOnlyFieldsFromBody extracts well-known read-only fields from the request body.
var readOnlyFieldNames = []string{"id", "created_at", "updated_at", "created_by", "updated_by", "role", "admin", "is_admin", "permissions"}

func extractReadOnlyFieldsFromBody(body []byte) map[string]interface{} {
	var parsed map[string]interface{}
	if json.Unmarshal(body, &parsed) != nil {
		// Fallback to defaults.
		return map[string]interface{}{
			"id":         99999,
			"created_at": "2020-01-01T00:00:00Z",
			"updated_at": "2020-01-01T00:00:00Z",
		}
	}
	readOnly := make(map[string]interface{})
	for _, name := range readOnlyFieldNames {
		if val, ok := parsed[name]; ok {
			readOnly[name] = val
		}
	}
	if len(readOnly) == 0 {
		return map[string]interface{}{
			"id":         99999,
			"created_at": "2020-01-01T00:00:00Z",
			"updated_at": "2020-01-01T00:00:00Z",
		}
	}
	return readOnly
}

// formatInjectedFields creates a human-readable summary of the injected fields.
func formatInjectedFields(fields map[string]interface{}) string {
	if len(fields) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(fields))
	for k, v := range fields {
		valJSON, _ := json.Marshal(v)
		parts = append(parts, fmt.Sprintf("%s=%s", k, string(valJSON)))
	}
	return strings.Join(parts, ", ")
}

