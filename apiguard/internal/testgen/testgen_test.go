package testgen

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

// buildTestIR creates a sample ParsedIR for testing.
func buildTestIR() ParsedIR {
	return ParsedIR{
		Endpoints: []IREndpoint{
			{
				Path:   "/api/users/{user_id}",
				Method: "GET",
				Parameters: []IRParameter{
					{Name: "user_id", Location: "path", Required: true},
				},
				Security: []string{"bearerAuth"},
				Tags:     []string{"users"},
			},
			{
				Path:   "/api/users",
				Method: "POST",
				RequestBody: &IRRequestBody{
					ContentTypes: []string{"application/json"},
					Required:     true,
				},
				Security: []string{"bearerAuth"},
				Tags:     []string{"users"},
			},
			{
				Path:   "/api/users/{user_id}",
				Method: "PUT",
				Parameters: []IRParameter{
					{Name: "user_id", Location: "path", Required: true},
				},
				RequestBody: &IRRequestBody{
					ContentTypes: []string{"application/json"},
					Required:     true,
				},
				Security: []string{"bearerAuth"},
				Tags:     []string{"users"},
			},
			{
				Path:   "/api/public/health",
				Method: "GET",
				Tags:   []string{"health"},
			},
			{
				Path:   "/api/public/reset",
				Method: "POST",
				Tags:   []string{"admin"},
			},
		},
		AuthSchemes: []IRAuthScheme{
			{Name: "bearerAuth", SchemeType: "http"},
		},
		Metadata: IRMetadata{
			BaseURL:    "https://api.example.com",
			APIVersion: "1.0.0",
			SchemaHash: "abc123def456",
		},
	}
}

// writeIRToTempFile writes the IR to a temp JSON file and returns the path.
func writeIRToTempFile(t *testing.T, ir ParsedIR) string {
	t.Helper()
	data, err := json.Marshal(ir)
	if err != nil {
		t.Fatalf("failed to marshal IR: %v", err)
	}
	tmpFile := filepath.Join(t.TempDir(), "test-ir.json")
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		t.Fatalf("failed to write temp IR file: %v", err)
	}
	return tmpFile
}

func TestGenerateBolaTests(t *testing.T) {
	logger := zerolog.Nop()
	gen := New(logger, "https://api.example.com", []string{"a1_bola"})

	ir := buildTestIR()
	irPath := writeIRToTempFile(t, ir)

	suite, err := gen.generateNative(context.Background(), irPath)
	if err != nil {
		t.Fatalf("generateNative failed: %v", err)
	}

	// Endpoints with ID params + auth: GET /api/users/{user_id}, PUT /api/users/{user_id}
	// Each should produce 2 BOLA test cases (sequential + cross-user).
	bolaCount := 0
	for _, tc := range suite.TestCases {
		if tc.ModuleID == "a1_bola" {
			bolaCount++
			if tc.EndpointPath != "/api/users/{user_id}" {
				t.Errorf("unexpected BOLA endpoint: %s", tc.EndpointPath)
			}
			if tc.Category != "bola_id_enum" && tc.Category != "bola_cross_user" {
				t.Errorf("unexpected BOLA category: %s", tc.Category)
			}
			if len(tc.Requests) < 2 {
				t.Errorf("BOLA test should have at least 2 requests, got %d", len(tc.Requests))
			}
			if len(tc.Expected.ExpectedStatusCodes) == 0 {
				t.Error("BOLA test should have expected status codes")
			}
		}
	}

	// 2 endpoints with ID params + auth * 2 test types = 4 BOLA tests.
	if bolaCount != 4 {
		t.Errorf("expected 4 BOLA test cases, got %d", bolaCount)
	}
}

func TestGenerateBolaSkipsEndpointsWithoutIDParams(t *testing.T) {
	logger := zerolog.Nop()
	gen := New(logger, "https://api.example.com", []string{"a1_bola"})

	ir := ParsedIR{
		Endpoints: []IREndpoint{
			{
				Path:     "/api/users",
				Method:   "GET",
				Security: []string{"bearerAuth"},
			},
		},
		Metadata: IRMetadata{SchemaHash: "test"},
	}
	irPath := writeIRToTempFile(t, ir)

	suite, err := gen.generateNative(context.Background(), irPath)
	if err != nil {
		t.Fatalf("generateNative failed: %v", err)
	}

	if len(suite.TestCases) != 0 {
		t.Errorf("expected 0 test cases for endpoint without ID params, got %d", len(suite.TestCases))
	}
}

func TestGenerateAuthRemovalTests(t *testing.T) {
	logger := zerolog.Nop()
	gen := New(logger, "https://api.example.com", []string{"a2_auth"})

	ir := buildTestIR()
	irPath := writeIRToTempFile(t, ir)

	suite, err := gen.generateNative(context.Background(), irPath)
	if err != nil {
		t.Fatalf("generateNative failed: %v", err)
	}

	authRemovalCount := 0
	expiredTokenCount := 0
	invalidTokenCount := 0
	unprotectedCount := 0
	for _, tc := range suite.TestCases {
		if tc.ModuleID != "a2_auth" {
			t.Errorf("unexpected module: %s", tc.ModuleID)
		}
		switch tc.Category {
		case "auth_removal":
			authRemovalCount++
			if tc.Requests[0].Auth != "none" {
				t.Error("auth_removal test should have Auth=none")
			}
		case "auth_token_expired":
			expiredTokenCount++
			if tc.Requests[0].Auth != "expired" {
				t.Error("auth_token_expired test should have Auth=expired")
			}
		case "auth_invalid_token":
			invalidTokenCount++
			if tc.Requests[0].Auth != "invalid" {
				t.Error("auth_invalid_token test should have Auth=invalid")
			}
		case "auth_unprotected_write":
			unprotectedCount++
		}
	}

	// 3 endpoints with security: GET /api/users/{user_id}, POST /api/users, PUT /api/users/{user_id}
	// Each gets 3 auth tests (removal, expired, invalid) = 9.
	if authRemovalCount != 3 {
		t.Errorf("expected 3 auth_removal tests, got %d", authRemovalCount)
	}
	if expiredTokenCount != 3 {
		t.Errorf("expected 3 auth_expired_token tests, got %d", expiredTokenCount)
	}
	if invalidTokenCount != 3 {
		t.Errorf("expected 3 auth_invalid_token tests, got %d", invalidTokenCount)
	}
	// 1 unprotected state-changing endpoint: POST /api/public/reset (no security, state-changing)
	if unprotectedCount != 1 {
		t.Errorf("expected 1 unprotected state change test, got %d", unprotectedCount)
	}
}

func TestGenerateMassAssignmentTests(t *testing.T) {
	logger := zerolog.Nop()
	gen := New(logger, "https://api.example.com", []string{"a3_mass_assignment"})

	ir := buildTestIR()
	irPath := writeIRToTempFile(t, ir)

	suite, err := gen.generateNative(context.Background(), irPath)
	if err != nil {
		t.Fatalf("generateNative failed: %v", err)
	}

	extraFieldsCount := 0
	readonlyCount := 0
	for _, tc := range suite.TestCases {
		if tc.ModuleID != "a3_mass_assignment" {
			t.Errorf("unexpected module: %s", tc.ModuleID)
		}
		switch tc.Category {
		case "mass_assign_extra_fields":
			extraFieldsCount++
			if tc.Requests[0].Body == nil {
				t.Error("extra_fields test should have a body")
			}
		case "mass_assign_readonly":
			readonlyCount++
			if tc.Requests[0].Body == nil {
				t.Error("readonly_fields test should have a body")
			}
		}
	}

	// POST /api/users (has request body) and PUT /api/users/{user_id} (has request body)
	// Each gets 2 mass assignment tests = 4 total.
	if extraFieldsCount != 2 {
		t.Errorf("expected 2 extra_fields tests, got %d", extraFieldsCount)
	}
	if readonlyCount != 2 {
		t.Errorf("expected 2 readonly_fields tests, got %d", readonlyCount)
	}
}

func TestNoModulesEnabled(t *testing.T) {
	logger := zerolog.Nop()
	// Pass explicit module list with a non-existent module.
	gen := New(logger, "https://api.example.com", []string{"nonexistent_module"})

	ir := buildTestIR()
	irPath := writeIRToTempFile(t, ir)

	suite, err := gen.generateNative(context.Background(), irPath)
	if err != nil {
		t.Fatalf("generateNative failed: %v", err)
	}

	if len(suite.TestCases) != 0 {
		t.Errorf("expected 0 test cases when no matching modules enabled, got %d", len(suite.TestCases))
	}
}

func TestModuleFiltering(t *testing.T) {
	logger := zerolog.Nop()
	// Only enable a1_bola.
	gen := New(logger, "https://api.example.com", []string{"a1_bola"})

	ir := buildTestIR()
	irPath := writeIRToTempFile(t, ir)

	suite, err := gen.generateNative(context.Background(), irPath)
	if err != nil {
		t.Fatalf("generateNative failed: %v", err)
	}

	for _, tc := range suite.TestCases {
		if tc.ModuleID != "a1_bola" {
			t.Errorf("expected only a1_bola tests, got module %s", tc.ModuleID)
		}
	}

	if len(suite.TestCases) == 0 {
		t.Error("expected some BOLA test cases")
	}
}

func TestEmptyModulesEnablesAll(t *testing.T) {
	logger := zerolog.Nop()
	// Empty modules list should enable all modules.
	gen := New(logger, "https://api.example.com", []string{})

	ir := buildTestIR()
	irPath := writeIRToTempFile(t, ir)

	suite, err := gen.generateNative(context.Background(), irPath)
	if err != nil {
		t.Fatalf("generateNative failed: %v", err)
	}

	modules := map[string]bool{}
	for _, tc := range suite.TestCases {
		modules[tc.ModuleID] = true
	}

	if !modules["a1_bola"] {
		t.Error("expected a1_bola tests when no modules filter")
	}
	if !modules["a2_auth"] {
		t.Error("expected a2_auth tests when no modules filter")
	}
	if !modules["a3_mass_assignment"] {
		t.Error("expected a3_mass_assignment tests when no modules filter")
	}
}

func TestGenerateWithInvalidIRPath(t *testing.T) {
	logger := zerolog.Nop()
	gen := New(logger, "https://api.example.com", []string{})

	_, err := gen.generateNative(context.Background(), "/nonexistent/path/ir.json")
	if err == nil {
		t.Error("expected error for invalid IR path")
	}
}

func TestGenerateWithInvalidJSON(t *testing.T) {
	logger := zerolog.Nop()
	gen := New(logger, "https://api.example.com", []string{})

	tmpFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmpFile, []byte("not valid json"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := gen.generateNative(context.Background(), tmpFile)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestIsIDParam(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"id", true},
		{"ID", true},
		{"uuid", true},
		{"user_id", true},
		{"userId", true},
		{"account_uuid", true},
		{"name", false},
		{"email", false},
		{"status", false},
	}

	for _, tt := range tests {
		if got := isIDParam(tt.name); got != tt.expected {
			t.Errorf("isIDParam(%q) = %v, want %v", tt.name, got, tt.expected)
		}
	}
}

func TestHasAuth(t *testing.T) {
	withAuth := &IREndpoint{Security: []string{"bearerAuth"}}
	withoutAuth := &IREndpoint{Security: []string{}}

	if !hasAuth(withAuth) {
		t.Error("expected hasAuth to return true for endpoint with security")
	}
	if hasAuth(withoutAuth) {
		t.Error("expected hasAuth to return false for endpoint without security")
	}
}

func TestTestSuiteMetadata(t *testing.T) {
	logger := zerolog.Nop()
	gen := New(logger, "https://api.example.com", []string{"a1_bola"})

	ir := buildTestIR()
	irPath := writeIRToTempFile(t, ir)

	suite, err := gen.generateNative(context.Background(), irPath)
	if err != nil {
		t.Fatalf("generateNative failed: %v", err)
	}

	if suite.TargetURL != "https://api.example.com" {
		t.Errorf("expected target URL https://api.example.com, got %s", suite.TargetURL)
	}
	if suite.SpecHash != "abc123def456" {
		t.Errorf("expected spec hash abc123def456, got %s", suite.SpecHash)
	}
}

func TestGenerateFallsBackToNative(t *testing.T) {
	logger := zerolog.Nop()
	gen := New(logger, "https://api.example.com", []string{"a1_bola"})

	ir := buildTestIR()
	irPath := writeIRToTempFile(t, ir)

	// Generate should fall back to native since no Rust binary exists.
	suite, err := gen.Generate(context.Background(), irPath)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(suite.TestCases) == 0 {
		t.Error("expected test cases from fallback generation")
	}
}
