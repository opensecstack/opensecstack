// Package prompt implements Module 3 (Prompt Injection Defence).
//
// STATUS: Phase 4.1 initial — Go-native pattern engine. Rust FFI
// port tracked as VG-003 (future optimisation for hot-path
// performance; Go version is the reference implementation for
// v0.1.0-alpha.0).
//
// Pattern library is code-resident. Runtime hot-reload via YAML is
// VG-future.
package prompt

import (
	"regexp"
)

// Category corresponds to the OWASP LLM Top 10 (2023 edition + custom).
type Category string

const (
	CategoryLLM01  Category = "OWASP-LLM01"  // Prompt Injection
	CategoryLLM02  Category = "OWASP-LLM02"  // Insecure Output Handling
	CategoryLLM04  Category = "OWASP-LLM04"  // Model DoS
	CategoryLLM06  Category = "OWASP-LLM06"  // Sensitive Info Disclosure
	CategoryLLM10  Category = "OWASP-LLM10"  // Model Theft
	CategoryCustom Category = "CUSTOM"
)

// Pattern is a single injection detection rule.
type Pattern struct {
	ID              string
	Category        Category
	Description     string
	AtlasTechnique  string // MITRE ATLAS technique ID, e.g. AML.T0051.000
	BaseScore       float64
	re              *regexp.Regexp
}

// MustCompilePattern is a helper for static pattern definitions.
func MustCompilePattern(id string, cat Category, desc, atlas string, base float64, pat string) Pattern {
	re, err := regexp.Compile(pat)
	if err != nil {
		panic("vertguard/prompt: bad static pattern " + id + ": " + err.Error())
	}
	return Pattern{
		ID:             id,
		Category:       cat,
		Description:    desc,
		AtlasTechnique: atlas,
		BaseScore:      base,
		re:             re,
	}
}

// Match is a single pattern hit within the scanned input.
type Match struct {
	PatternID       string   `json:"pattern_id"`
	Category        Category `json:"category"`
	Description     string   `json:"description"`
	AtlasTechnique  string   `json:"atlas_technique,omitempty"`
	ByteRange       [2]int   `json:"byte_range"`
	Confidence      float64  `json:"confidence"`
}

// Scan applies the pattern against the input and returns any matches.
func (p *Pattern) Scan(input string) []Match {
	locs := p.re.FindAllStringIndex(input, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]Match, 0, len(locs))
	for _, loc := range locs {
		out = append(out, Match{
			PatternID:      p.ID,
			Category:       p.Category,
			Description:    p.Description,
			AtlasTechnique: p.AtlasTechnique,
			ByteRange:      [2]int{loc[0], loc[1]},
			Confidence:     p.BaseScore,
		})
	}
	return out
}

// DefaultLibrary is the code-resident pattern set shipped with
// v0.1.0-alpha.0. Target: expand to 50+ patterns through VG-001 / VG-002.
// Every entry here has corresponding tests in tests/prompt/ and
// false-positive cases in tests/fp/prompt/.
var DefaultLibrary = []Pattern{
	// ── LLM01 — Prompt Injection (direct overrides) ─────────────────
	MustCompilePattern(
		"LLM01.instruction_override.v1",
		CategoryLLM01,
		"Attempts to override prior instructions",
		"AML.T0051.000",
		0.95,
		`(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?|orders?|directives?)`,
	),
	MustCompilePattern(
		"LLM01.instruction_override.v2",
		CategoryLLM01,
		"Claims of new instructions overriding previous ones",
		"AML.T0051.000",
		0.9,
		`(?i)(new|updated|revised)\s+instructions?:?\s*(override|supersede|replace)`,
	),
	MustCompilePattern(
		"LLM01.role_replace.v1",
		CategoryLLM01,
		"Persona takeover attempt",
		"AML.T0051.000",
		0.85,
		`(?i)you\s+are\s+now\s+(?:a|an)?\s*(DAN|developer|admin|root|god|evil|unfiltered|unrestricted)`,
	),
	MustCompilePattern(
		"LLM01.system_prompt_reveal.v1",
		CategoryLLM01,
		"Direct request to reveal system prompt",
		"AML.T0057",
		0.9,
		`(?i)(show|reveal|print|display|output|tell\s+me)\s+(your|the)\s+(system\s+)?(prompt|instructions|rules|configuration)`,
	),
	MustCompilePattern(
		"LLM01.developer_mode.v1",
		CategoryLLM01,
		"Developer mode / debug mode activation attempt",
		"AML.T0051.000",
		0.85,
		`(?i)(enable|activate|enter)\s+(developer|debug|admin|god|sudo|root|unrestricted|jailbreak)\s+mode`,
	),

	// ── LLM01 — Jailbreaks ──────────────────────────────────────────
	MustCompilePattern(
		"LLM01.jailbreak.dan.v1",
		CategoryLLM01,
		"DAN-family jailbreak",
		"AML.T0051.000",
		0.95,
		`(?i)\b(DAN|Do Anything Now|STAN|AIM|Machiavelli)\b.*(prompt|persona|mode|role)`,
	),
	MustCompilePattern(
		"LLM01.jailbreak.hypothetical.v1",
		CategoryLLM01,
		"Hypothetical/fictional framing to bypass safety",
		"AML.T0051.000",
		0.7,
		`(?i)hypothetically,?\s+(if|suppose)\s+(you|we)\s+(could|were|had)\s+(no\s+)?(rules|restrictions|ethics|safety)`,
	),
	MustCompilePattern(
		"LLM01.jailbreak.no_restrictions.v1",
		CategoryLLM01,
		"Claim of no restrictions / uncensored",
		"AML.T0051.000",
		0.8,
		`(?i)(respond|answer|reply)\s+(?:as|like)\s+(?:if|though)\s+(?:you|we)\s+(?:have|had)\s+no\s+(?:restrictions|rules|ethics|filters|guidelines)`,
	),

	// ── LLM01 — Indirect injection ──────────────────────────────────
	MustCompilePattern(
		"LLM01.indirect.embedded_instruction.v1",
		CategoryLLM01,
		"Embedded instruction marker in content",
		"AML.T0051.001",
		0.8,
		`(?i)<!--\s*(system|instruction|prompt):\s*.+\s*-->`,
	),
	MustCompilePattern(
		"LLM01.indirect.assistant_markers.v1",
		CategoryLLM01,
		"Fake assistant / user message markers",
		"AML.T0051.001",
		0.85,
		`(?i)\b(Assistant:|User:|System:|</system>|<\|im_start\|>|<\|im_end\|>)`,
	),

	// ── LLM06 — Sensitive Information Disclosure ────────────────────
	MustCompilePattern(
		"LLM06.training_exfil.v1",
		CategoryLLM06,
		"Attempt to exfiltrate training data",
		"AML.T0057",
		0.85,
		`(?i)(repeat|recite|output|print).*?(training\s+data|examples\s+from\s+training|memorised)`,
	),
	MustCompilePattern(
		"LLM06.memory_exfil.v1",
		CategoryLLM06,
		"Attempt to exfiltrate prior-conversation content",
		"AML.T0057",
		0.75,
		`(?i)(recall|show|reveal|print)\s+(?:all\s+)?(previous|prior|earlier)\s+(conversations?|sessions?|messages?)`,
	),
	MustCompilePattern(
		"LLM06.credentials_exfil.v1",
		CategoryLLM06,
		"Attempt to exfiltrate credentials or secrets from context",
		"AML.T0024",
		0.95,
		`(?i)(show|reveal|leak|extract|print).{0,30}\b(api[_\s-]?key|secret|token|password|credential)s?\b`,
	),

	// ── LLM04 — Model DoS ───────────────────────────────────────────
	MustCompilePattern(
		"LLM04.recursive_generation.v1",
		CategoryLLM04,
		"Recursive self-prompt pattern (potential DoS)",
		"AML.T0029",
		0.6,
		`(?i)repeat\s+(?:this|the above|yourself)\s+(?:\d+\s+)?(?:times|forever|indefinitely)`,
	),

	// ── LLM10 — Model extraction probes ─────────────────────────────
	MustCompilePattern(
		"LLM10.version_probe.v1",
		CategoryLLM10,
		"Model-identity probe (version extraction)",
		"AML.T0024",
		0.5,
		`(?i)(what\s+(model|version|llm)\s+(are\s+)?you|which\s+(gpt|claude|gemini|llama|mistral))`,
	),
}
