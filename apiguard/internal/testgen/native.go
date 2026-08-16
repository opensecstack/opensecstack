package testgen

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
)

// generateNative creates test cases using pure Go logic.
// This is the fallback when the Rust testgen binary is not available.
func (g *Generator) generateNative(ctx context.Context, irPath string) (*TestSuite, error) {
	// Read the IR JSON. irPath is an internally generated temp path from the
	// scanner (see internal/scanner/scanner.go), not user- or network-controlled.
	data, err := os.ReadFile(irPath) // #nosec G304 -- trusted internal temp path, see comment above
	if err != nil {
		return nil, fmt.Errorf("cannot read IR file: %w", err)
	}

	var ir ParsedIR
	if err := json.Unmarshal(data, &ir); err != nil {
		return nil, fmt.Errorf("cannot parse IR JSON: %w", err)
	}

	suite := &TestSuite{
		TargetURL: g.targetURL,
		SpecHash:  ir.Metadata.SchemaHash,
		TestCases: []TestCase{},
	}

	for _, endpoint := range ir.Endpoints {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if g.moduleEnabled("a1_bola") {
			suite.TestCases = append(suite.TestCases, g.generateBolaTests(&endpoint)...)
		}
		if g.moduleEnabled("a2_auth") {
			suite.TestCases = append(suite.TestCases, g.generateAuthTests(&endpoint)...)
		}
		if g.moduleEnabled("a3_mass_assignment") {
			suite.TestCases = append(suite.TestCases, g.generateMassAssignmentTests(&endpoint)...)
		}
	}

	return suite, nil
}

// moduleEnabled checks if a module is in the enabled list.
// An empty modules list means all modules are enabled.
func (g *Generator) moduleEnabled(id string) bool {
	if len(g.modules) == 0 {
		return true
	}
	for _, m := range g.modules {
		if m == id {
			return true
		}
	}
	return false
}

// isIDParam checks if a parameter name looks like an identifier field.
func isIDParam(name string) bool {
	lower := strings.ToLower(name)
	if lower == "id" || lower == "uuid" {
		return true
	}
	if strings.HasSuffix(lower, "_id") || strings.HasSuffix(lower, "id") {
		return true
	}
	if strings.HasSuffix(lower, "_uuid") {
		return true
	}
	return false
}

// hasAuth checks if an endpoint has security schemes defined.
func hasAuth(endpoint *IREndpoint) bool {
	return len(endpoint.Security) > 0
}

// generateTestID creates a new unique test case ID.
func generateTestID() string {
	return uuid.New().String()
}

// generateBolaTests creates BOLA (Broken Object Level Authorization) test cases.
// Targets endpoints with ID-like path parameters that require authentication.
func (g *Generator) generateBolaTests(endpoint *IREndpoint) []TestCase {
	var cases []TestCase

	// Find ID-like path parameters.
	var idParams []IRParameter
	for _, p := range endpoint.Parameters {
		if p.Location == "path" && isIDParam(p.Name) {
			idParams = append(idParams, p)
		}
	}

	// Only generate BOLA tests for endpoints with ID params and auth.
	if len(idParams) == 0 || !hasAuth(endpoint) {
		return cases
	}

	// Test case: Sequential ID enumeration.
	// Try accessing resources with sequential IDs to detect enumeration.
	cases = append(cases, TestCase{
		ID:             generateTestID(),
		ModuleID:       "a1_bola",
		EndpointPath:   endpoint.Path,
		EndpointMethod: endpoint.Method,
		Category:       "bola_id_enum",
		Requests: []TestRequest{
			{
				Method:      endpoint.Method,
				Path:        replaceIDParams(endpoint.Path, idParams, "1"),
				Headers:     [][]string{{"Content-Type", "application/json"}},
				Auth:        "valid_user_a",
				Description: "Access resource with ID 1 as user A",
			},
			{
				Method:      endpoint.Method,
				Path:        replaceIDParams(endpoint.Path, idParams, "2"),
				Headers:     [][]string{{"Content-Type", "application/json"}},
				Auth:        "valid_user_a",
				Description: "Access resource with ID 2 as user A (should fail if user A does not own resource 2)",
			},
		},
		Expected: ExpectedBehavior{
			ShouldSucceed:        false,
			ExpectedStatusCodes:  []int{401, 403, 404},
			VulnerabilityIfFails: "BOLA: Sequential ID enumeration allows accessing other users' resources",
		},
	})

	// Test case: Cross-user access.
	// Try accessing another user's resource with a different user's token.
	cases = append(cases, TestCase{
		ID:             generateTestID(),
		ModuleID:       "a1_bola",
		EndpointPath:   endpoint.Path,
		EndpointMethod: endpoint.Method,
		Category:       "bola_cross_user",
		Requests: []TestRequest{
			{
				Method:      endpoint.Method,
				Path:        replaceIDParams(endpoint.Path, idParams, "1"),
				Headers:     [][]string{{"Content-Type", "application/json"}},
				Auth:        "valid_user_a",
				Description: "Access resource owned by user A using user A's token (baseline)",
			},
			{
				Method:      endpoint.Method,
				Path:        replaceIDParams(endpoint.Path, idParams, "1"),
				Headers:     [][]string{{"Content-Type", "application/json"}},
				Auth:        "valid_user_b",
				Description: "Access resource owned by user A using user B's token (should be denied)",
			},
		},
		Expected: ExpectedBehavior{
			ShouldSucceed:        false,
			ExpectedStatusCodes:  []int{401, 403, 404},
			VulnerabilityIfFails: "BOLA: Cross-user access allows one user to read/modify another user's resources",
		},
	})

	return cases
}

// generateAuthTests creates authentication/authorization test cases.
func (g *Generator) generateAuthTests(endpoint *IREndpoint) []TestCase {
	var cases []TestCase

	if hasAuth(endpoint) {
		// Test: Auth removal (no token).
		cases = append(cases, TestCase{
			ID:             generateTestID(),
			ModuleID:       "a2_auth",
			EndpointPath:   endpoint.Path,
			EndpointMethod: endpoint.Method,
			Category:       "auth_removal",
			Requests: []TestRequest{
				{
					Method:      endpoint.Method,
					Path:        endpoint.Path,
					Headers:     [][]string{{"Content-Type", "application/json"}},
					Auth:        "none",
					Description: "Request with no authentication token",
				},
			},
			Expected: ExpectedBehavior{
				ShouldSucceed:        false,
				ExpectedStatusCodes:  []int{401, 403},
				VulnerabilityIfFails: "Broken Authentication: Endpoint accessible without any authentication",
			},
		})

		// Test: Expired token.
		cases = append(cases, TestCase{
			ID:             generateTestID(),
			ModuleID:       "a2_auth",
			EndpointPath:   endpoint.Path,
			EndpointMethod: endpoint.Method,
			Category:       "auth_token_expired",
			Requests: []TestRequest{
				{
					Method:      endpoint.Method,
					Path:        endpoint.Path,
					Headers:     [][]string{{"Content-Type", "application/json"}},
					Auth:        "expired",
					Description: "Request with an expired authentication token",
				},
			},
			Expected: ExpectedBehavior{
				ShouldSucceed:        false,
				ExpectedStatusCodes:  []int{401, 403},
				VulnerabilityIfFails: "Broken Authentication: Endpoint accepts expired tokens",
			},
		})

		// Test: Invalid token.
		cases = append(cases, TestCase{
			ID:             generateTestID(),
			ModuleID:       "a2_auth",
			EndpointPath:   endpoint.Path,
			EndpointMethod: endpoint.Method,
			Category:       "auth_invalid_token",
			Requests: []TestRequest{
				{
					Method:      endpoint.Method,
					Path:        endpoint.Path,
					Headers:     [][]string{{"Content-Type", "application/json"}},
					Auth:        "invalid",
					Description: "Request with a malformed/invalid authentication token",
				},
			},
			Expected: ExpectedBehavior{
				ShouldSucceed:        false,
				ExpectedStatusCodes:  []int{401, 403},
				VulnerabilityIfFails: "Broken Authentication: Endpoint accepts invalid tokens",
			},
		})
	} else {
		// For unprotected state-changing endpoints, flag as suspicious.
		method := strings.ToUpper(endpoint.Method)
		if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
			cases = append(cases, TestCase{
				ID:             generateTestID(),
				ModuleID:       "a2_auth",
				EndpointPath:   endpoint.Path,
				EndpointMethod: endpoint.Method,
				Category:       "auth_unprotected_write",
				Requests: []TestRequest{
					{
						Method:      endpoint.Method,
						Path:        endpoint.Path,
						Headers:     [][]string{{"Content-Type", "application/json"}},
						Auth:        "none",
						Description: "State-changing endpoint with no authentication requirement defined in spec",
					},
				},
				Expected: ExpectedBehavior{
					ShouldSucceed:        false,
					ExpectedStatusCodes:  []int{401, 403},
					VulnerabilityIfFails: "Broken Authentication: State-changing endpoint has no authentication requirement",
				},
			})
		}
	}

	return cases
}

// generateMassAssignmentTests creates mass assignment test cases.
// Targets POST/PUT/PATCH endpoints with request bodies.
func (g *Generator) generateMassAssignmentTests(endpoint *IREndpoint) []TestCase {
	var cases []TestCase

	method := strings.ToUpper(endpoint.Method)
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return cases
	}

	if endpoint.RequestBody == nil {
		return cases
	}

	// Test: Extra privileged fields injection.
	extraFields := map[string]interface{}{
		"admin":       true,
		"role":        "admin",
		"is_admin":    true,
		"isAdmin":     true,
		"permissions": []string{"*"},
	}
	extraFieldsJSON, _ := json.Marshal(extraFields) //nolint:errcheck // extraFields is a hardcoded literal of JSON-safe types, cannot fail

	cases = append(cases, TestCase{
		ID:             generateTestID(),
		ModuleID:       "a3_mass_assignment",
		EndpointPath:   endpoint.Path,
		EndpointMethod: endpoint.Method,
		Category:       "mass_assign_extra_fields",
		Requests: []TestRequest{
			{
				Method:      endpoint.Method,
				Path:        endpoint.Path,
				Headers:     [][]string{{"Content-Type", "application/json"}},
				Body:        json.RawMessage(extraFieldsJSON),
				Auth:        "valid_user_a",
				Description: "Inject extra privileged fields (admin, role, is_admin, permissions)",
			},
		},
		Expected: ExpectedBehavior{
			ShouldSucceed:        false,
			ExpectedStatusCodes:  []int{400, 422},
			VulnerabilityIfFails: "Mass Assignment: API accepts and processes privileged fields that should be server-controlled",
		},
	})

	// Test: Read-only field overwrite.
	readOnlyFields := map[string]interface{}{
		"id":         999999,
		"created_at": "2000-01-01T00:00:00Z",
		"updated_at": "2000-01-01T00:00:00Z",
	}
	readOnlyJSON, _ := json.Marshal(readOnlyFields) //nolint:errcheck // readOnlyFields is a hardcoded literal of JSON-safe types, cannot fail

	cases = append(cases, TestCase{
		ID:             generateTestID(),
		ModuleID:       "a3_mass_assignment",
		EndpointPath:   endpoint.Path,
		EndpointMethod: endpoint.Method,
		Category:       "mass_assign_readonly",
		Requests: []TestRequest{
			{
				Method:      endpoint.Method,
				Path:        endpoint.Path,
				Headers:     [][]string{{"Content-Type", "application/json"}},
				Body:        json.RawMessage(readOnlyJSON),
				Auth:        "valid_user_a",
				Description: "Attempt to overwrite read-only fields (id, created_at, updated_at)",
			},
		},
		Expected: ExpectedBehavior{
			ShouldSucceed:        false,
			ExpectedStatusCodes:  []int{400, 422},
			VulnerabilityIfFails: "Mass Assignment: API allows overwriting read-only/server-managed fields",
		},
	})

	return cases
}

// replaceIDParams replaces ID-like path parameters with the given value.
func replaceIDParams(path string, idParams []IRParameter, value string) string {
	result := path
	for _, p := range idParams {
		result = strings.ReplaceAll(result, "{"+p.Name+"}", value)
	}
	return result
}
