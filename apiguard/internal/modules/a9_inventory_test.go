package modules

import (
	"context"
	"testing"
)

// TestA9VersionEndpointFinding verifies that a finding is produced when a probed
// older API version path returns HTTP 200.
func TestA9VersionEndpointFinding(t *testing.T) {
	// The test case path is /v3/users. candidateVersionPrefixes probes /v1, /v2, /api/v1, etc.
	// /v3 is skipped (current version). So /v1/users, /v2/users, /api/v1/users, /api/v2/users, /api/v3/users
	// are probed in order. Return 200 for the first probe (/v1/users) to trigger finding.
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"version":"v1"}`), // /v1/users → 200 → finding
		},
	}

	mod := &InventoryModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a9-version",
				Category: "inventory_api_version",
				Method:   "GET",
				Path:     "/v3/users",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for old API version, got none")
	}
}

// TestA9DebugEndpointFinding verifies that a finding is produced when a debug path
// such as /metrics returns HTTP 200.
func TestA9DebugEndpointFinding(t *testing.T) {
	// runDebugEndpoints iterates debugEndpointPaths:
	// /actuator, /actuator/health, /actuator/env, /_debug, /debug, /status, /info,
	// /metrics, /.well-known/, /swagger-ui.html, /api-docs, /graphql
	// Return 404 for the first 7 paths, then 200 for /metrics (index 7).
	responses := make([]*HTTPResponse, 8)
	for i := 0; i < 7; i++ {
		responses[i] = resp(404, `{}`)
	}
	responses[7] = resp(200, `{"metrics":"data"}`) // /metrics

	exec := &mockExecutor{responses: responses}

	mod := &InventoryModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a9-debug",
				Category: "inventory_debug_endpoint",
				Method:   "GET",
				Path:     "/api/resource",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for debug endpoint, got none")
	}
}

// TestA9NoFinding verifies that no findings are produced when all probes return 404.
func TestA9NoFinding(t *testing.T) {
	// All probes return 404 — no version or debug findings.
	exec := &mockExecutor{} // mock returns 404 for all out-of-range indices

	mod := &InventoryModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc-a9-nofind-version",
				Category: "inventory_api_version",
				Method:   "GET",
				Path:     "/v3/users",
			},
			{
				ID:       "tc-a9-nofind-debug",
				Category: "inventory_debug_endpoint",
				Method:   "GET",
				Path:     "/api/resource",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// TestA9IDAndName verifies the module ID and name.
func TestA9IDAndName(t *testing.T) {
	mod := &InventoryModule{}
	if mod.ID() != "a9_inventory" {
		t.Errorf("expected ID a9_inventory, got %s", mod.ID())
	}
	if mod.Name() == "" {
		t.Error("expected non-empty Name()")
	}
}
