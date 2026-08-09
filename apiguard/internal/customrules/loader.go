package customrules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadRulesFromDir loads all *.yaml and *.yml files from the given directory.
// Files that fail to parse are skipped and their errors are collected but do
// not abort the load; the caller can decide whether to treat them as fatal.
func LoadRulesFromDir(dir string) ([]CustomRule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("customrules: cannot read directory %q: %w", dir, err)
	}

	var all []CustomRule
	var errs []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, name)
		rules, err := LoadRulesFromFile(path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		all = append(all, rules...)
	}

	if len(errs) > 0 {
		return all, fmt.Errorf("customrules: errors loading files:\n  %s", strings.Join(errs, "\n  "))
	}

	return all, nil
}

// LoadRulesFromFile loads all rules declared in a single YAML file.
// The file must use the top-level "rules:" key (see RuleFile).
func LoadRulesFromFile(path string) ([]CustomRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("customrules: cannot read file %q: %w", path, err)
	}

	var rf RuleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("customrules: cannot parse YAML in %q: %w", path, err)
	}

	// Apply default: rules are enabled unless explicitly set to false.
	// yaml.v3 unmarshals a missing bool field as the zero value (false).
	// We cannot distinguish "field absent" from "field set to false" with a
	// plain bool, so we use a separate raw-node pass to check whether the
	// key appeared in the document.
	var rawFile struct {
		Rules []map[string]interface{} `yaml:"rules"`
	}
	_ = yaml.Unmarshal(data, &rawFile) //nolint:errcheck // errors already caught above; ignore here
	for i := range rf.Rules {
		if i >= len(rawFile.Rules) {
			// Raw parse shorter than typed parse — treat as enabled.
			rf.Rules[i].Enabled = true
			continue
		}
		if _, present := rawFile.Rules[i]["enabled"]; !present {
			// "enabled" key was absent; apply default of true.
			rf.Rules[i].Enabled = true
		}
		// If the key is present, honour whatever value yaml.v3 decoded.
	}

	return rf.Rules, nil
}

// Validate checks a set of loaded rules for structural correctness.
// It returns one error per problem found rather than stopping at the first.
func Validate(rules []CustomRule) []error {
	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
		"info":     true,
	}

	validCheckTypes := map[string]bool{
		"header_missing":             true,
		"header_value":               true,
		"status_code":                true,
		"response_body_contains":     true,
		"response_body_not_contains": true,
		"response_time_exceeds":      true,
	}

	var errs []error

	seenIDs := make(map[string]bool)

	for i, rule := range rules {
		prefix := fmt.Sprintf("rule[%d]", i)
		if rule.ID != "" {
			prefix = fmt.Sprintf("rule %q", rule.ID)
		}

		if rule.ID == "" {
			errs = append(errs, fmt.Errorf("%s: id is required", prefix))
		} else if seenIDs[rule.ID] {
			errs = append(errs, fmt.Errorf("%s: duplicate rule id %q", prefix, rule.ID))
		} else {
			seenIDs[rule.ID] = true
		}

		if rule.Name == "" {
			errs = append(errs, fmt.Errorf("%s: name is required", prefix))
		}

		sev := strings.ToLower(rule.Severity)
		if rule.Severity == "" {
			errs = append(errs, fmt.Errorf("%s: severity is required (critical|high|medium|low|info)", prefix))
		} else if !validSeverities[sev] {
			errs = append(errs, fmt.Errorf("%s: unknown severity %q (must be critical|high|medium|low|info)", prefix, rule.Severity))
		}

		if len(rule.Checks) == 0 {
			errs = append(errs, fmt.Errorf("%s: at least one check is required", prefix))
		}

		for j, check := range rule.Checks {
			cprefix := fmt.Sprintf("%s check[%d]", prefix, j)

			if check.Type == "" {
				errs = append(errs, fmt.Errorf("%s: type is required", cprefix))
			} else if !validCheckTypes[check.Type] {
				errs = append(errs, fmt.Errorf("%s: unknown check type %q", cprefix, check.Type))
			}

			if check.Target == "" {
				errs = append(errs, fmt.Errorf("%s: target is required (use \"*\" to match all paths)", cprefix))
			}

			if check.Method == "" {
				errs = append(errs, fmt.Errorf("%s: method is required (use \"*\" to match all methods)", cprefix))
			}

			if check.Message == "" {
				errs = append(errs, fmt.Errorf("%s: message is required", cprefix))
			}

			// Type-specific param validation.
			switch check.Type {
			case "header_missing", "header_value":
				if check.Params["header"] == "" {
					errs = append(errs, fmt.Errorf("%s: params.header is required for check type %q", cprefix, check.Type))
				}
				if check.Type == "header_value" && check.Params["pattern"] == "" {
					errs = append(errs, fmt.Errorf("%s: params.pattern is required for check type \"header_value\"", cprefix))
				}
			case "status_code":
				if check.Params["expected"] == "" {
					errs = append(errs, fmt.Errorf("%s: params.expected is required for check type \"status_code\" (comma-separated status codes, e.g. \"401,403\")", cprefix))
				}
			case "response_body_contains", "response_body_not_contains":
				if check.Params["text"] == "" {
					errs = append(errs, fmt.Errorf("%s: params.text is required for check type %q", cprefix, check.Type))
				}
			case "response_time_exceeds":
				if check.Params["ms"] == "" {
					errs = append(errs, fmt.Errorf("%s: params.ms is required for check type \"response_time_exceeds\" (threshold in milliseconds)", cprefix))
				}
			}
		}
	}

	return errs
}
