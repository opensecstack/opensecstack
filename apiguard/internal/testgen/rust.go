package testgen

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// generateViaRust invokes the Rust testgen binary to generate test cases.
func (g *Generator) generateViaRust(ctx context.Context, irPath string) (*TestSuite, error) {
	// Create a temp file for the testgen output.
	tmpDir := os.TempDir()
	outputPath := filepath.Join(tmpDir, fmt.Sprintf("apiguard-testgen-%s.json", uuid.New().String()))
	defer os.Remove(outputPath)

	// Look for the Rust testgen binary.
	testgenBin := "apiguard-testgen"
	if binPath := os.Getenv("APIGUARD_TESTGEN_BIN"); binPath != "" {
		testgenBin = binPath
	}

	// Build module list argument.
	modulesArg := strings.Join(g.modules, ",")

	// testgenBin defaults to a fixed binary name and is otherwise only overridable via
	// the operator-configured APIGUARD_TESTGEN_BIN env var (trusted, not request input).
	// Arguments are passed as a structured exec.Cmd argument list (no shell is invoked),
	// so there is no command-injection vector here; g.targetURL was already validated by
	// validateTargetURL and irPath/outputPath are internally generated temp paths.
	cmd := exec.CommandContext(ctx, testgenBin, //nolint:gosec // structured argv, no shell; args are internally generated or pre-validated, see comment above
		"generate",
		"--ir", irPath,
		"--target", g.targetURL,
		"--modules", modulesArg,
		"--output", outputPath,
	)
	cmd.Stderr = os.Stderr

	g.logger.Debug().
		Str("testgen_bin", testgenBin).
		Str("ir_path", irPath).
		Str("output", outputPath).
		Msg("invoking Rust testgen")

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("testgen execution failed: %w", err)
	}

	// Read the testgen output.
	data, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read testgen output: %w", err)
	}

	var suite TestSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		return nil, fmt.Errorf("failed to parse testgen JSON: %w", err)
	}

	return &suite, nil
}
