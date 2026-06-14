package testgen

import (
	"context"
	"encoding/json"

	"github.com/rs/zerolog"
)

// TestSuite matches the Rust testgen output.
type TestSuite struct {
	TargetURL string     `json:"target_url"`
	SpecHash  string     `json:"spec_hash"`
	TestCases []TestCase `json:"test_cases"`
}

// TestCase represents a single generated test case.
type TestCase struct {
	ID             string           `json:"id"`
	ModuleID       string           `json:"module_id"`
	EndpointPath   string           `json:"endpoint_path"`
	EndpointMethod string           `json:"endpoint_method"`
	Category       string           `json:"category"`
	Requests       []TestRequest    `json:"requests"`
	Expected       ExpectedBehavior `json:"expected"`
}

// TestRequest represents a single HTTP request within a test case.
type TestRequest struct {
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Headers     [][]string      `json:"headers"`
	Body        json.RawMessage `json:"body,omitempty"`
	Auth        string          `json:"auth"`
	Description string          `json:"description"`
}

// ExpectedBehavior defines what a correct API should do for this test case.
type ExpectedBehavior struct {
	ShouldSucceed        bool   `json:"should_succeed"`
	ExpectedStatusCodes  []int  `json:"expected_status_codes"`
	VulnerabilityIfFails string `json:"vulnerability_if_fails"`
}

// Generator creates test cases from parsed API specs.
type Generator struct {
	logger    zerolog.Logger
	modules   []string
	targetURL string
}

// New creates a new test generator.
func New(logger zerolog.Logger, targetURL string, modules []string) *Generator {
	return &Generator{
		logger:    logger,
		modules:   modules,
		targetURL: targetURL,
	}
}

// Generate creates test cases by invoking the Rust testgen binary.
// It takes the path to the parsed IR JSON file and returns a TestSuite.
func (g *Generator) Generate(ctx context.Context, irPath string) (*TestSuite, error) {
	// Try to use Rust testgen binary
	suite, err := g.generateViaRust(ctx, irPath)
	if err != nil {
		g.logger.Warn().Err(err).Msg("Rust testgen not available, falling back to Go generator")
		// Fall back to Go-native generation
		return g.generateNative(ctx, irPath)
	}
	return suite, nil
}
