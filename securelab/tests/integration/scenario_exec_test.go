package integration_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestScenarioExecBolaBasic loads scenarios/api/bola-basic.yaml, provisions a
// test environment (skipped if Docker is not available), executes the scenario,
// and asserts the run completed without error.
func TestScenarioExecBolaBasic(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("Docker not available — skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Start test environment
	t.Log("Starting test environment...")
	upCmd := exec.CommandContext(ctx, "docker", "compose",
		"-f", "../../docker-compose.test.yml",
		"up", "-d", "--wait")
	upCmd.Dir = testDataDir(t)
	if out, err := upCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to start test environment: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		downCmd := exec.Command("docker", "compose",
			"-f", "../../docker-compose.test.yml", "down", "-v")
		downCmd.Dir = testDataDir(t)
		_ = downCmd.Run()
	})

	// Load scenario
	scenarioPath := "../../scenarios/api/bola-basic.yaml"
	if _, err := os.Stat(scenarioPath); err != nil {
		t.Fatalf("Scenario file not found: %s", scenarioPath)
	}

	// Execute scenario via CLI (dry-run in CI to avoid network requirements)
	// In a full integration environment remove --dry-run
	runCmd := exec.CommandContext(ctx, "go", "run", "../../cmd/securelab/main.go",
		"run",
		"--scenario", scenarioPath,
		"--target-url", "http://localhost:9090",
		"--dry-run",
	)

	out, err := runCmd.CombinedOutput()
	t.Logf("Scenario output:\n%s", out)

	if err != nil {
		t.Errorf("Scenario execution failed: %v", err)
	}
}

func dockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	return cmd.Run() == nil
}

func testDataDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
