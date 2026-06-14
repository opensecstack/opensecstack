package prompt

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Severity classifies a rule's intrinsic risk independent of context.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "med"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityScore translates a rule pack severity into the [0,1] base
// confidence consumed by the existing scorer. Calibrated so the scorer's
// thresholds (clean=0.3, block=0.7) keep their documented meaning when
// the rule pack ships v1.0 categories.
func severityScore(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return 0.95
	case SeverityHigh:
		return 0.85
	case SeverityMedium:
		return 0.55
	case SeverityLow:
		return 0.3
	default:
		return 0.5
	}
}

// RulePackFile mirrors the on-disk rule pack schema (rules/v1.json).
type RulePackFile struct {
	Version     string     `json:"version"`
	Description string     `json:"description"`
	Rules       []RuleSpec `json:"rules"`
}

// RuleSpec is the JSON-encoded form of a single detection rule. The
// loader compiles each Pattern + Severity into a runtime Pattern so the
// scanner can consume it without further allocation per scan.
type RuleSpec struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	Atlas       string   `json:"atlas"`
	Pattern     string   `json:"pattern"`
	Description string   `json:"description"`
	Example     string   `json:"example"`
}

// LoadRulePack reads and compiles a JSON rule pack from disk. The
// returned slice is suitable for NewScanner. An empty path returns
// (nil, nil) — the caller may then fall back to DefaultLibrary.
func LoadRulePack(path string) ([]Pattern, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule pack %q: %w", path, err)
	}
	return ParseRulePack(raw)
}

// ParseRulePack compiles an in-memory rule pack. Exposed so callers
// (and tests) can validate raw JSON without touching the filesystem.
func ParseRulePack(raw []byte) ([]Pattern, error) {
	var pack RulePackFile
	if err := json.Unmarshal(raw, &pack); err != nil {
		return nil, fmt.Errorf("parse rule pack: %w", err)
	}
	if len(pack.Rules) == 0 {
		return nil, fmt.Errorf("rule pack contains zero rules")
	}
	out := make([]Pattern, 0, len(pack.Rules))
	seen := make(map[string]struct{}, len(pack.Rules))
	for i, r := range pack.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("rule[%d]: missing id", i)
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("rule[%d]: duplicate id %q", i, r.ID)
		}
		seen[r.ID] = struct{}{}
		if r.Pattern == "" {
			return nil, fmt.Errorf("rule[%d] %s: missing pattern", i, r.ID)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: compile: %w", r.ID, err)
		}
		cat := r.Category
		if cat == "" {
			cat = CategoryCustom
		}
		out = append(out, Pattern{
			ID:             r.ID,
			Category:       cat,
			Description:    r.Description,
			AtlasTechnique: r.Atlas,
			BaseScore:      severityScore(r.Severity),
			re:             re,
		})
	}
	return out, nil
}
