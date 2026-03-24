package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/testgen"
)

// MassAssignmentModule detects OWASP API3:2023 Broken Object Property Level Authorization
// (mass assignment) vulnerabilities by injecting extra or read-only fields into API requests.
type MassAssignmentModule struct {
	executor *HTTPExecutor
	logger   zerolog.Logger
}

// NewMassAssignmentModule creates a new MassAssignmentModule.
func NewMassAssignmentModule(executor *HTTPExecutor, logger zerolog.Logger) *MassAssignmentModule {
	return &MassAssignmentModule{
		executor: executor,
		logger:   logger.With().Str("module", "a3_mass_assignment").Logger(),
	}
}

// ID returns the module identifier.
func (m *MassAssignmentModule) ID() string { return "a3_mass_assignment" }

// Name returns the human-readable module name.
func (m *MassAssignmentModule) Name() string {
	return "Broken Object Property Level Authorization"
}

// Execute runs all mass assignment test cases and returns findings.
func (m *MassAssignmentModule) Execute(ctx context.Context, cases []testgen.TestCase) ([]domain.Finding, error) {
	var findings []domain.Finding

	for _, tc := range cases {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		m.logger.Info().
			Str("case_id", tc.ID).
			Str("category", tc.Category).
			Str("endpoint", tc.EndpointMethod+" "+tc.EndpointPath).
			Msg("executing test case")

		var caseFindings []domain.Finding
		var err error

		switch tc.Category {
		case "mass_assign_extra_fields":
			caseFindings, err = m.executeExtraFields(ctx, tc)
		case "mass_assign_readonly":
			caseFindings, err = m.executeReadOnly(ctx, tc)
		default:
			m.logger.Warn().Str("category", tc.Category).Msg("unknown category, skipping")
			continue
		}

		if err != nil {
			m.logger.Error().Err(err).Str("case_id", tc.ID).Msg("test case execution failed")
			continue
		}

		findings = append(findings, caseFindings...)
	}

	m.logger.Info().Int("findings", len(findings)).Msg("mass assignment module completed")
	return findings, nil
}

// executeExtraFields tests whether the API accepts additional fields not in the schema.
func (m *MassAssignmentModule) executeExtraFields(ctx context.Context, tc testgen.TestCase) ([]domain.Finding, error) {
	if len(tc.Requests) < 2 {
		return nil, fmt.Errorf("expected at least 2 requests (baseline + attack), got %d", len(tc.Requests))
	}

	baselineReq := tc.Requests[0]
	attackReq := tc.Requests[1]

	// Send baseline request (normal request without extra fields).
	baselineResp, err := m.executor.ExecuteRequest(ctx, baselineReq)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	// Send attack request (with extra fields injected).
	attackResp, err := m.executor.ExecuteRequest(ctx, attackReq)
	if err != nil {
		return nil, fmt.Errorf("attack request failed: %w", err)
	}

	method := tc.EndpointMethod
	path := tc.EndpointPath

	m.logger.Debug().
		Int("baseline_status", baselineResp.StatusCode).
		Int("attack_status", attackResp.StatusCode).
		Msg("comparing baseline and attack responses")

	// If the server properly rejects unknown fields with a validation error, no finding.
	if attackResp.StatusCode == 400 || attackResp.StatusCode == 422 {
		m.logger.Info().Msg("server properly rejects extra fields with validation error")
		return nil, nil
	}

	var findings []domain.Finding

	// Extract the extra fields that were injected in the attack request body.
	injectedFields := diffRequestBodies(baselineReq.Body, attackReq.Body)
	if len(injectedFields) == 0 {
		// Fallback: check for common mass assignment fields.
		injectedFields = map[string]interface{}{
			"admin":      true,
			"role":       "admin",
			"is_admin":   true,
			"id":         99999,
			"created_at": "2020-01-01T00:00:00Z",
			"updated_at": "2020-01-01T00:00:00Z",
		}
	}

	if attackResp.StatusCode >= 200 && attackResp.StatusCode < 300 {
		// Check if any injected fields are reflected in the response.
		reflectedFields := findReflectedFields(attackResp.Body, injectedFields)

		if len(reflectedFields) > 0 {
			// HIGH: Mass assignment confirmed — injected fields appear in response.
			for _, fieldName := range reflectedFields {
				finding := domain.Finding{
					OWASPId:        "API3:2023",
					ModuleID:       "a3_mass_assignment",
					Title:          "Mass Assignment Vulnerability on " + method + " " + path,
					Description:    "The endpoint accepts and processes additional fields that were not part of the original schema. Injected field: " + fieldName,
					Severity:       domain.SeverityHigh,
					CVSSScore:      7.5,
					CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
					EndpointPath:   path,
					EndpointMethod: method,
					Evidence: domain.Evidence{
						Request:  formatRequest(attackReq),
						Response: formatResponse(attackResp),
						Detail: map[string]interface{}{
							"injected_field":   fieldName,
							"injected_value":   injectedFields[fieldName],
							"baseline_status":  baselineResp.StatusCode,
							"attack_status":    attackResp.StatusCode,
							"field_reflected":  true,
							"category":         "mass_assign_extra_fields",
						},
					},
					Remediation: "Implement allowlist-based input validation. Only accept fields explicitly defined in the API schema. Reject or ignore unknown properties.",
					Status:      domain.FindingStatusOpen,
				}
				findings = append(findings, finding)
			}
		} else {
			// Check if the response is identical to the baseline (fields silently ignored).
			changedFields := diffResponses(baselineResp.Body, attackResp.Body)

			if len(changedFields) == 0 {
				// Fields silently ignored — same as baseline. INFO level, no finding reported.
				m.logger.Info().
					Str("endpoint", method+" "+path).
					Msg("extra fields silently ignored, response identical to baseline")
			} else {
				// MEDIUM: Server accepts extra fields without reflecting them but response differs.
				finding := domain.Finding{
					OWASPId:        "API3:2023",
					ModuleID:       "a3_mass_assignment",
					Title:          "Extra Fields Accepted Without Validation on " + method + " " + path,
					Description:    "The endpoint accepts requests containing additional fields not defined in the API schema. While the fields are not directly reflected in the response, the server does not reject them, indicating a potential mass assignment risk.",
					Severity:       domain.SeverityMedium,
					CVSSScore:      5.3,
					CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
					EndpointPath:   path,
					EndpointMethod: method,
					Evidence: domain.Evidence{
						Request:  formatRequest(attackReq),
						Response: formatResponse(attackResp),
						Detail: map[string]interface{}{
							"baseline_status": baselineResp.StatusCode,
							"attack_status":   attackResp.StatusCode,
							"changed_fields":  changedFields,
							"category":        "mass_assign_extra_fields",
						},
					},
					Remediation: "Configure strict input validation to reject requests containing unexpected fields (additionalProperties: false in OpenAPI).",
					Status:      domain.FindingStatusOpen,
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// executeReadOnly tests whether the API allows modification of read-only fields.
func (m *MassAssignmentModule) executeReadOnly(ctx context.Context, tc testgen.TestCase) ([]domain.Finding, error) {
	if len(tc.Requests) < 1 {
		return nil, fmt.Errorf("expected at least 1 request, got %d", len(tc.Requests))
	}

	attackReq := tc.Requests[0]

	// Send the attack request with read-only fields in the body.
	attackResp, err := m.executor.ExecuteRequest(ctx, attackReq)
	if err != nil {
		return nil, fmt.Errorf("attack request failed: %w", err)
	}

	method := tc.EndpointMethod
	path := tc.EndpointPath

	m.logger.Debug().
		Int("attack_status", attackResp.StatusCode).
		Msg("checking read-only field overwrite response")

	// If the server rejects the request with a validation error, it is properly protected.
	if attackResp.StatusCode == 400 || attackResp.StatusCode == 422 {
		m.logger.Info().Msg("server properly rejects read-only field overwrite")
		return nil, nil
	}

	var findings []domain.Finding

	if attackResp.StatusCode >= 200 && attackResp.StatusCode < 300 {
		// Extract read-only fields from the request body.
		readOnlyFields := extractReadOnlyFields(attackReq.Body)
		if len(readOnlyFields) == 0 {
			// Fallback: check standard read-only fields.
			readOnlyFields = map[string]interface{}{
				"id":         99999,
				"created_at": "2020-01-01T00:00:00Z",
				"updated_at": "2020-01-01T00:00:00Z",
			}
		}

		// Check if the read-only field values are reflected in the response.
		reflectedFields := findReflectedFields(attackResp.Body, readOnlyFields)

		if len(reflectedFields) > 0 {
			// HIGH: Read-only fields can be overwritten.
			for _, fieldName := range reflectedFields {
				finding := domain.Finding{
					OWASPId:        "API3:2023",
					ModuleID:       "a3_mass_assignment",
					Title:          "Read-Only Field Overwrite on " + method + " " + path,
					Description:    "The endpoint allows modification of read-only field: " + fieldName,
					Severity:       domain.SeverityHigh,
					CVSSScore:      6.5,
					CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
					EndpointPath:   path,
					EndpointMethod: method,
					Evidence: domain.Evidence{
						Request:  formatRequest(attackReq),
						Response: formatResponse(attackResp),
						Detail: map[string]interface{}{
							"readonly_field":  fieldName,
							"injected_value":  readOnlyFields[fieldName],
							"field_reflected": true,
							"category":        "mass_assign_readonly",
						},
					},
					Remediation: "Enforce read-only constraints on fields like id, created_at, updated_at at the API layer, not just the database layer.",
					Status:      domain.FindingStatusOpen,
				}
				findings = append(findings, finding)
			}
		} else {
			// 200 but values not reflected — fields ignored, no finding.
			m.logger.Info().
				Str("endpoint", method+" "+path).
				Msg("read-only fields ignored by server, no overwrite detected")
		}
	}

	return findings, nil
}

// responseContainsField checks if a JSON response body contains a specific field with the expected value.
func responseContainsField(body []byte, fieldName string, expectedValue interface{}) bool {
	parsed := extractJSONFields(body)
	if parsed == nil {
		return false
	}

	actual, exists := parsed[fieldName]
	if !exists {
		return false
	}

	// Compare values by marshalling both to JSON for a normalized comparison.
	expectedJSON, err1 := json.Marshal(expectedValue)
	actualJSON, err2 := json.Marshal(actual)
	if err1 != nil || err2 != nil {
		return false
	}

	return string(expectedJSON) == string(actualJSON)
}

// extractJSONFields parses the response body as JSON and returns a flat map of fields.
// It handles both top-level objects and nested "data" wrappers.
func extractJSONFields(body []byte) map[string]interface{} {
	if len(body) == 0 {
		return nil
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}

	// Also check inside a "data" wrapper, which is common in API responses.
	if data, ok := parsed["data"]; ok {
		if dataMap, ok := data.(map[string]interface{}); ok {
			// Merge top-level and data-level fields, preferring data-level.
			merged := make(map[string]interface{})
			for k, v := range parsed {
				merged[k] = v
			}
			for k, v := range dataMap {
				merged[k] = v
			}
			return merged
		}
	}

	return parsed
}

// diffResponses finds fields that differ between baseline and attack response bodies.
func diffResponses(baseline, attack []byte) []string {
	baselineFields := extractJSONFields(baseline)
	attackFields := extractJSONFields(attack)

	if baselineFields == nil || attackFields == nil {
		return nil
	}

	var changed []string

	// Find fields that are new or changed in the attack response.
	for key, attackVal := range attackFields {
		baseVal, exists := baselineFields[key]
		if !exists {
			changed = append(changed, key)
			continue
		}

		baseJSON, _ := json.Marshal(baseVal)
		attackJSON, _ := json.Marshal(attackVal)
		if string(baseJSON) != string(attackJSON) {
			changed = append(changed, key)
		}
	}

	return changed
}

// diffRequestBodies extracts the fields that are present in the attack body but absent
// from the baseline body (i.e., the injected extra fields).
func diffRequestBodies(baseline, attack json.RawMessage) map[string]interface{} {
	var baseFields map[string]interface{}
	var attackFields map[string]interface{}

	if err := json.Unmarshal(baseline, &baseFields); err != nil {
		return nil
	}
	if err := json.Unmarshal(attack, &attackFields); err != nil {
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

// findReflectedFields checks which of the injected fields appear in the response body
// with the expected values, and returns the list of field names that were reflected.
func findReflectedFields(responseBody []byte, injectedFields map[string]interface{}) []string {
	var reflected []string

	for fieldName, expectedValue := range injectedFields {
		if responseContainsField(responseBody, fieldName, expectedValue) {
			reflected = append(reflected, fieldName)
		}
	}

	return reflected
}

// extractReadOnlyFields extracts well-known read-only fields from the request body.
var readOnlyFieldNames = []string{"id", "created_at", "updated_at", "created_by", "updated_by"}

func extractReadOnlyFields(body json.RawMessage) map[string]interface{} {
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}

	readOnly := make(map[string]interface{})
	for _, name := range readOnlyFieldNames {
		if val, ok := parsed[name]; ok {
			readOnly[name] = val
		}
	}

	// Also check for common privilege-escalation fields used in read-only tests.
	for _, name := range []string{"role", "admin", "is_admin", "permissions"} {
		if val, ok := parsed[name]; ok {
			readOnly[name] = val
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
