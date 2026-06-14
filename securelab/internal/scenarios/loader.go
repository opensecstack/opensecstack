// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// StepSpec describes a single attack step within a scenario.
type StepSpec struct {
	// Kind identifies the attack primitive to execute.
	// Valid values are defined by ValidStepKinds.
	Kind string `yaml:"kind"`

	// Params is an open-ended map of primitive-specific configuration.
	// Keys and value types depend on the chosen Kind.
	Params map[string]any `yaml:"params,omitempty"`
}

// ScenarioSpec is the top-level structure parsed from a scenario YAML file.
type ScenarioSpec struct {
	// Name is a unique human-readable identifier for the scenario.
	Name string `yaml:"name"`

	// Description explains what the scenario tests.
	Description string `yaml:"description,omitempty"`

	// MitreTechniqueIDs is the list of ATT&CK technique IDs covered (e.g. "T1190").
	MitreTechniqueIDs []string `yaml:"mitre_technique_ids,omitempty"`

	// Tags provides arbitrary labels used for filtering and reporting.
	Tags []string `yaml:"tags,omitempty"`

	// Severity is the risk classification: low | medium | high | critical.
	Severity string `yaml:"severity"`

	// Timeout is the maximum wall-clock duration for the entire scenario run.
	// If zero the platform default from Config.ScenarioTimeout is used.
	Timeout time.Duration `yaml:"timeout,omitempty"`

	// Steps is the ordered list of attack primitives to execute.
	Steps []StepSpec `yaml:"steps"`
}

// scenarioYAML is an intermediate representation used during unmarshalling so
// that Timeout can be parsed as a string (e.g. "5m") before conversion.
type scenarioYAML struct {
	Name               string     `yaml:"name"`
	Description        string     `yaml:"description"`
	MitreTechniqueIDs  []string   `yaml:"mitre_technique_ids"`
	Tags               []string   `yaml:"tags"`
	Severity           string     `yaml:"severity"`
	Timeout            string     `yaml:"timeout"`
	Steps              []StepSpec `yaml:"steps"`
}

// LoadFromYAML parses a YAML-encoded scenario definition and returns a
// *ScenarioSpec. It returns an error if the YAML is structurally invalid;
// semantic validation should be performed separately via Validate.
func LoadFromYAML(data []byte) (*ScenarioSpec, error) {
	var raw scenarioYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("scenarios: parse yaml: %w", err)
	}

	spec := &ScenarioSpec{
		Name:              raw.Name,
		Description:       raw.Description,
		MitreTechniqueIDs: raw.MitreTechniqueIDs,
		Tags:              raw.Tags,
		Severity:          raw.Severity,
		Steps:             raw.Steps,
	}

	if raw.Timeout != "" {
		d, err := time.ParseDuration(raw.Timeout)
		if err != nil {
			return nil, fmt.Errorf("scenarios: parse timeout %q: %w", raw.Timeout, err)
		}
		spec.Timeout = d
	}

	if spec.MitreTechniqueIDs == nil {
		spec.MitreTechniqueIDs = []string{}
	}
	if spec.Tags == nil {
		spec.Tags = []string{}
	}
	if spec.Steps == nil {
		spec.Steps = []StepSpec{}
	}

	return spec, nil
}
