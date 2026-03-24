package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/testgen"
)

// BolaModule implements the OWASP API1:2023 Broken Object Level Authorization check.
type BolaModule struct {
	executor *HTTPExecutor
	logger   zerolog.Logger
}

// NewBolaModule creates a new BOLA module.
func NewBolaModule(executor *HTTPExecutor, logger zerolog.Logger) *BolaModule {
	return &BolaModule{
		executor: executor,
		logger:   logger.With().Str("module", "a1_bola").Logger(),
	}
}

// ID returns the module identifier.
func (m *BolaModule) ID() string { return "a1_bola" }

// Name returns the human-readable module name.
func (m *BolaModule) Name() string { return "Broken Object Level Authorization" }

// Execute runs all BOLA test cases and returns findings.
func (m *BolaModule) Execute(ctx context.Context, cases []testgen.TestCase) ([]domain.Finding, error) {
	var findings []domain.Finding

	for i := range cases {
		tc := &cases[i]
		m.logger.Info().
			Str("test_case", tc.ID).
			Str("category", tc.Category).
			Str("endpoint", fmt.Sprintf("%s %s", tc.EndpointMethod, tc.EndpointPath)).
			Int("requests", len(tc.Requests)).
			Msg("executing test case")

		var tcFindings []domain.Finding
		var err error

		switch tc.Category {
		case "bola_id_enum":
			tcFindings, err = m.executeIDEnumeration(ctx, tc)
		case "bola_cross_user":
			tcFindings, err = m.executeCrossUser(ctx, tc)
		default:
			m.logger.Warn().Str("category", tc.Category).Msg("unknown BOLA test category, skipping")
			continue
		}

		if err != nil {
			m.logger.Error().Err(err).Str("test_case", tc.ID).Msg("test case execution failed")
			continue
		}

		findings = append(findings, tcFindings...)
	}

	m.logger.Info().Int("findings", len(findings)).Msg("BOLA module completed")
	return findings, nil
}

// executeIDEnumeration tests whether different object IDs can be accessed with the same auth token.
func (m *BolaModule) executeIDEnumeration(ctx context.Context, tc *testgen.TestCase) ([]domain.Finding, error) {
	if len(tc.Requests) < 2 {
		m.logger.Debug().Msg("ID enumeration requires at least 2 requests, skipping")
		return nil, nil
	}

	// Send baseline request (first request with valid auth).
	baselineReq := tc.Requests[0]
	baselineResp, err := m.executor.ExecuteRequest(ctx, baselineReq)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	m.logger.Debug().
		Int("status", baselineResp.StatusCode).
		Str("path", baselineReq.Path).
		Msg("baseline response received")

	// If baseline doesn't succeed, we can't reliably test enumeration.
	if baselineResp.StatusCode < 200 || baselineResp.StatusCode >= 300 {
		m.logger.Debug().Int("status", baselineResp.StatusCode).Msg("baseline request did not succeed, skipping")
		return nil, nil
	}

	var findings []domain.Finding

	// Send remaining requests with different IDs.
	for i := 1; i < len(tc.Requests); i++ {
		enumReq := tc.Requests[i]
		enumResp, err := m.executor.ExecuteRequest(ctx, enumReq)
		if err != nil {
			m.logger.Warn().Err(err).Str("path", enumReq.Path).Msg("enum request failed, skipping")
			continue
		}

		endpoint := fmt.Sprintf("%s %s", tc.EndpointMethod, tc.EndpointPath)

		// Check: non-existent IDs returning 200 instead of 404 (information disclosure).
		if enumResp.StatusCode == 200 && !responsesAreSimilar(baselineResp, enumResp) {
			// Different data for different IDs with same auth = potential BOLA.
			finding := domain.Finding{
				ID:             uuid.New().String(),
				OWASPId:        "API1:2023",
				ModuleID:       "a1_bola",
				Title:          "Broken Object Level Authorization - ID Enumeration on " + endpoint,
				Description:    fmt.Sprintf("The endpoint %s returns different data for different object IDs using the same authentication token. An attacker can enumerate and access objects belonging to other users by manipulating the object ID parameter. Request to %s returned status %d with different data than the baseline request to %s.", endpoint, enumReq.Path, enumResp.StatusCode, baselineReq.Path),
				Severity:       domain.SeverityHigh,
				CVSSScore:      7.5,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
				EndpointPath:   tc.EndpointPath,
				EndpointMethod: tc.EndpointMethod,
				Evidence: domain.Evidence{
					Request:  formatRequest(enumReq),
					Response: formatResponse(enumResp),
					Detail: map[string]interface{}{
						"baseline_status": baselineResp.StatusCode,
						"enum_status":     enumResp.StatusCode,
						"baseline_path":   baselineReq.Path,
						"enum_path":       enumReq.Path,
						"test_case_id":    tc.ID,
					},
				},
				Remediation: "Implement object-level authorization checks. Verify that the authenticated user has permission to access the requested object before returning its data. Use the user's session/token to determine ownership and enforce access control on every object-level operation.",
				Status:      domain.FindingStatusOpen,
			}
			findings = append(findings, finding)
			m.logger.Warn().
				Str("path", enumReq.Path).
				Int("status", enumResp.StatusCode).
				Msg("potential BOLA: different IDs return different data")
		} else if enumResp.StatusCode == 200 && responsesAreSimilar(baselineResp, enumResp) {
			// Same data for different IDs - could be static/shared data, less likely BOLA.
			m.logger.Debug().
				Str("path", enumReq.Path).
				Msg("same response for different ID, likely shared resource")
		}

		// Check: IDs that should not exist still returning 200.
		if enumReq.Description != "" && strings.Contains(strings.ToLower(enumReq.Description), "non-existent") {
			if enumResp.StatusCode == 200 {
				finding := domain.Finding{
					ID:             uuid.New().String(),
					OWASPId:        "API1:2023",
					ModuleID:       "a1_bola",
					Title:          "Information Disclosure via ID Enumeration on " + endpoint,
					Description:    fmt.Sprintf("The endpoint %s returns HTTP 200 for a non-existent object ID (%s) instead of 404 Not Found. This may indicate the API does not properly validate object existence or authorization, enabling attackers to enumerate valid and invalid IDs.", endpoint, enumReq.Path),
					Severity:       domain.SeverityMedium,
					CVSSScore:      5.3,
					CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
					EndpointPath:   tc.EndpointPath,
					EndpointMethod: tc.EndpointMethod,
					Evidence: domain.Evidence{
						Request:  formatRequest(enumReq),
						Response: formatResponse(enumResp),
						Detail: map[string]interface{}{
							"expected_status": 404,
							"actual_status":   enumResp.StatusCode,
							"test_case_id":    tc.ID,
						},
					},
					Remediation: "Return HTTP 404 Not Found for requests to non-existent resources. Ensure object existence checks are performed after authorization checks to avoid disclosing which IDs are valid.",
					Status:      domain.FindingStatusOpen,
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// executeCrossUser tests whether one user can access another user's objects.
func (m *BolaModule) executeCrossUser(ctx context.Context, tc *testgen.TestCase) ([]domain.Finding, error) {
	if len(tc.Requests) < 2 {
		m.logger.Debug().Msg("cross-user test requires at least 2 requests, skipping")
		return nil, nil
	}

	// Find the "valid" auth request (user A baseline) and "other_user" auth request (user B).
	var validReq, otherReq *testgen.TestRequest
	for i := range tc.Requests {
		switch tc.Requests[i].Auth {
		case "valid":
			validReq = &tc.Requests[i]
		case "other_user":
			otherReq = &tc.Requests[i]
		}
	}

	if validReq == nil || otherReq == nil {
		m.logger.Debug().Msg("cross-user test missing valid or other_user request, skipping")
		return nil, nil
	}

	// Send request as user A (valid auth).
	validResp, err := m.executor.ExecuteRequest(ctx, *validReq)
	if err != nil {
		return nil, fmt.Errorf("valid user request failed: %w", err)
	}

	m.logger.Debug().
		Int("status", validResp.StatusCode).
		Str("path", validReq.Path).
		Msg("user A (valid) response received")

	// If user A can't access the resource, we can't test cross-user.
	if validResp.StatusCode < 200 || validResp.StatusCode >= 300 {
		m.logger.Debug().Int("status", validResp.StatusCode).Msg("user A request did not succeed, skipping cross-user test")
		return nil, nil
	}

	// Send same request as user B (other_user auth).
	otherResp, err := m.executor.ExecuteRequest(ctx, *otherReq)
	if err != nil {
		return nil, fmt.Errorf("other user request failed: %w", err)
	}

	m.logger.Debug().
		Int("status", otherResp.StatusCode).
		Str("path", otherReq.Path).
		Msg("user B (other_user) response received")

	var findings []domain.Finding
	endpoint := fmt.Sprintf("%s %s", tc.EndpointMethod, tc.EndpointPath)

	// If user B gets 200 with same/similar data as user A, BOLA is confirmed.
	if otherResp.StatusCode >= 200 && otherResp.StatusCode < 300 {
		if responsesAreSimilar(validResp, otherResp) {
			finding := domain.Finding{
				ID:             uuid.New().String(),
				OWASPId:        "API1:2023",
				ModuleID:       "a1_bola",
				Title:          "Broken Object Level Authorization - Cross-User Access on " + endpoint,
				Description:    fmt.Sprintf("The endpoint %s allows User B to access User A's object. Both users received HTTP %d responses with similar data, confirming that the API does not enforce object-level authorization. An attacker authenticated as any user can access objects belonging to other users.", endpoint, otherResp.StatusCode),
				Severity:       domain.SeverityHigh,
				CVSSScore:      7.5,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
				EndpointPath:   tc.EndpointPath,
				EndpointMethod: tc.EndpointMethod,
				Evidence: domain.Evidence{
					Request:  formatRequest(*otherReq),
					Response: formatResponse(otherResp),
					Detail: map[string]interface{}{
						"user_a_status":    validResp.StatusCode,
						"user_b_status":    otherResp.StatusCode,
						"responses_match":  true,
						"user_a_body_size": len(validResp.Body),
						"user_b_body_size": len(otherResp.Body),
						"test_case_id":     tc.ID,
					},
				},
				Remediation: "Implement object-level authorization checks. Verify that the authenticated user has permission to access the requested object before returning its data. Use the user's session/token to determine ownership and enforce access control on every object-level operation.",
				Status:      domain.FindingStatusOpen,
			}
			findings = append(findings, finding)
			m.logger.Warn().
				Str("endpoint", endpoint).
				Msg("BOLA confirmed: User B can access User A's object")
		} else {
			// User B got 200 but different data - might be accessing their own object.
			m.logger.Debug().
				Str("endpoint", endpoint).
				Msg("User B got 200 but different data, may be accessing own object")
		}
	} else if otherResp.StatusCode == 401 || otherResp.StatusCode == 403 {
		// Properly protected - user B is denied access.
		m.logger.Info().
			Str("endpoint", endpoint).
			Int("status", otherResp.StatusCode).
			Msg("endpoint properly protected: cross-user access denied")
	}

	return findings, nil
}

// dynamicFieldPattern matches common dynamic fields in JSON responses that should
// be ignored when comparing responses (timestamps, generated IDs, etc.).
var dynamicFieldPattern = regexp.MustCompile(
	`"(?:created_at|updated_at|modified_at|timestamp|date|time|` +
		`request_id|trace_id|correlation_id|` +
		`token|csrf|nonce|session)"\s*:\s*"[^"]*"`,
)

// responsesAreSimilar compares two HTTP responses, ignoring dynamic fields like
// timestamps and generated IDs. Returns true if the responses are structurally similar.
func responsesAreSimilar(a, b *HTTPResponse) bool {
	// Different status codes are never similar.
	if a.StatusCode != b.StatusCode {
		return false
	}

	// Normalize response bodies by removing dynamic fields.
	normA := normalizebody(a.Body)
	normB := normalizebody(b.Body)

	// Exact match after normalization.
	if bytes.Equal(normA, normB) {
		return true
	}

	// Check structural similarity for JSON responses.
	if isJSON(a.Body) && isJSON(b.Body) {
		return jsonStructurallySimilar(a.Body, b.Body)
	}

	// For non-JSON, check if body lengths are within 10% of each other.
	if len(normA) == 0 && len(normB) == 0 {
		return true
	}
	if len(normA) == 0 || len(normB) == 0 {
		return false
	}
	ratio := float64(len(normA)) / float64(len(normB))
	return ratio >= 0.9 && ratio <= 1.1
}

// normalizebody removes dynamic fields from a response body.
func normalizebody(body []byte) []byte {
	return dynamicFieldPattern.ReplaceAll(body, []byte(`"_dynamic_":"_removed_"`))
}

// isJSON checks if the data looks like JSON.
func isJSON(data []byte) bool {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return false
	}
	return (data[0] == '{' || data[0] == '[')
}

// jsonStructurallySimilar compares two JSON payloads by their top-level key structure.
func jsonStructurallySimilar(a, b []byte) bool {
	var objA, objB map[string]json.RawMessage
	if json.Unmarshal(a, &objA) != nil || json.Unmarshal(b, &objB) != nil {
		// If not objects, try arrays.
		var arrA, arrB []json.RawMessage
		if json.Unmarshal(a, &arrA) != nil || json.Unmarshal(b, &arrB) != nil {
			return false
		}
		// Arrays are similar if they have the same length.
		return len(arrA) == len(arrB)
	}

	// Objects are similar if they have the same set of keys.
	if len(objA) != len(objB) {
		return false
	}
	for key := range objA {
		if _, ok := objB[key]; !ok {
			return false
		}
	}
	return true
}
