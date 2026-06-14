package scenarios_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ScenarioStep represents a single step in a scenario.
type ScenarioStep struct {
	Kind   string         `yaml:"kind"`
	Name   string         `yaml:"name"`
	Params map[string]any `yaml:"params"`
}

// Scenario represents the top-level structure of a scenario YAML file.
type Scenario struct {
	Name              string         `yaml:"name"`
	Description       string         `yaml:"description"`
	MITRETechniqueIDs []string       `yaml:"mitre_technique_ids"`
	Tags              []string       `yaml:"tags"`
	Severity          string         `yaml:"severity"`
	Timeout           string         `yaml:"timeout"`
	Steps             []ScenarioStep `yaml:"steps"`
}

// Validate checks that a Scenario has all required fields populated correctly.
func Validate(s Scenario, filename string) []string {
	var errs []string

	if strings.TrimSpace(s.Name) == "" {
		errs = append(errs, "name is required")
	}
	if strings.TrimSpace(s.Description) == "" {
		errs = append(errs, "description is required")
	}
	if len(s.MITRETechniqueIDs) == 0 {
		errs = append(errs, "mitre_technique_ids must contain at least one entry")
	}
	for _, id := range s.MITRETechniqueIDs {
		if !strings.HasPrefix(id, "T") {
			errs = append(errs, "mitre_technique_ids entries must start with 'T', got: "+id)
		}
	}

	validSeverities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !validSeverities[s.Severity] {
		errs = append(errs, "severity must be one of: low, medium, high, critical — got: "+s.Severity)
	}

	if strings.TrimSpace(s.Timeout) == "" {
		errs = append(errs, "timeout is required")
	}
	if len(s.Steps) == 0 {
		errs = append(errs, "steps must contain at least one entry")
	}
	for i, step := range s.Steps {
		if strings.TrimSpace(step.Kind) == "" {
			errs = append(errs, "step[%d]: kind is required")
			_ = i
		}
	}

	return errs
}

// TestValidateAllScenarios loads every .yaml file under scenarios/, parses it,
// and validates the structure. The test fails if any scenario is invalid.
func TestValidateAllScenarios(t *testing.T) {
	// Walk from repo root — scenarios/ is two levels up from tests/scenarios/
	scenariosRoot := filepath.Join("..", "..", "scenarios")

	var scenarioFiles []string
	err := filepath.WalkDir(scenariosRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			scenarioFiles = append(scenarioFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk scenarios directory: %v", err)
	}

	if len(scenarioFiles) == 0 {
		t.Fatal("No scenario YAML files found under scenarios/")
	}

	t.Logf("Found %d scenario files", len(scenarioFiles))

	for _, path := range scenarioFiles {
		path := path // capture for t.Run closure
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("Failed to read %s: %v", path, err)
			}

			var s Scenario
			if err := yaml.Unmarshal(data, &s); err != nil {
				t.Fatalf("Failed to parse YAML in %s: %v", path, err)
			}

			errs := Validate(s, path)
			for _, e := range errs {
				t.Errorf("%s: %s", path, e)
			}
		})
	}
}
