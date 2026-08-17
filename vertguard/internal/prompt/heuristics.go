package prompt

import (
	"math"
	"unicode"
	"unicode/utf8"
)

// Heuristic IDs. Stable strings — they end up in audit logs and
// dashboards, so rename only with a migration.
const (
	HeuristicLongToken   = "rp.v1.heur.long_token" // #nosec G101 -- heuristic ID string, not a credential
	HeuristicHighEntropy = "rp.v1.heur.high_entropy"
	HeuristicMixedScript = "rp.v1.heur.mixed_script"
	HeuristicInvisibles  = "rp.v1.heur.invisible_chars"
	HeuristicTokenFlood  = "rp.v1.heur.token_flood" // #nosec G101 -- heuristic ID string, not a credential
)

// HeuristicLimits bounds the token-level checks. Defaults come from
// DefaultHeuristicLimits — operators do not currently override these
// (a future ticket can plumb them through PromptConfig if needed).
type HeuristicLimits struct {
	LongTokenLen        int     // single whitespace-delimited token byte length
	HighEntropyMinLen   int     // minimum chunk length to qualify
	HighEntropyMinBits  float64 // Shannon-entropy threshold (bits/char)
	MixedScriptMinRunes int     // minimum runes before mixed-script flags
	InvisiblesMin       int     // minimum invisible chars in a row
	TokenFloodMin       int     // repeated identical token threshold
}

// DefaultHeuristicLimits matches the documented v1.0 detector
// behaviour. Tuned against the bundled corpus to keep false-positive
// rate <1% on benign English/Albanian/Spanish text.
var DefaultHeuristicLimits = HeuristicLimits{
	LongTokenLen:        120,
	HighEntropyMinLen:   80,
	HighEntropyMinBits:  4.5,
	MixedScriptMinRunes: 8,
	InvisiblesMin:       3,
	TokenFloodMin:       12,
}

// RunHeuristics scans input with the token-level detectors and returns
// Match-shaped results. The returned slice composes naturally with
// regex matches in Scanner.Scan.
//
// All heuristics are deterministic and stateless. A heuristic with no
// signal returns nothing; the scorer aggregates whatever survives.
func RunHeuristics(input string, lim HeuristicLimits) []Match {
	if input == "" {
		return nil
	}
	out := make([]Match, 0, 4)

	if m, ok := checkInvisibles(input, lim); ok {
		out = append(out, m)
	}
	if m, ok := checkMixedScript(input, lim); ok {
		out = append(out, m)
	}
	out = append(out, scanTokens(input, lim)...)
	return out
}

// invisible reports whether r is a zero-width / BiDi / format control
// codepoint that has no business in a user prompt. The Trojan-Source
// class (BiDi overrides) is included because attackers use them to
// flip the visual order of code/text.
func invisible(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF: // zero-width / word joiner / BOM
		return true
	case 0x202A, 0x202B, 0x202C, 0x202D, 0x202E: // BiDi embedding/override
		return true
	case 0x2066, 0x2067, 0x2068, 0x2069: // BiDi isolates
		return true
	}
	return false
}

func checkInvisibles(input string, lim HeuristicLimits) (Match, bool) {
	count := 0
	first := -1
	last := -1
	pos := 0
	for _, r := range input {
		size := utf8.RuneLen(r)
		if size < 0 {
			size = 1
		}
		if invisible(r) {
			if first < 0 {
				first = pos
			}
			last = pos + size
			count++
		}
		pos += size
	}
	if count < lim.InvisiblesMin {
		return Match{}, false
	}
	conf := 0.6 + 0.05*float64(count-lim.InvisiblesMin)
	if conf > 0.95 {
		conf = 0.95
	}
	return Match{
		PatternID:      HeuristicInvisibles,
		Category:       CategoryLLM01,
		Description:    "invisible / bidi control characters",
		AtlasTechnique: "AML.T0051.001",
		ByteRange:      [2]int{first, last},
		Confidence:     conf,
	}, true
}

// runeScript returns the bucket a rune belongs to for homoglyph
// detection. Only the buckets we actually compare are enumerated;
// everything else is "other" and ignored.
func runeScript(r rune) string {
	switch {
	case unicode.Is(unicode.Latin, r):
		return "latin"
	case unicode.Is(unicode.Cyrillic, r):
		return "cyrillic"
	case unicode.Is(unicode.Greek, r):
		return "greek"
	}
	return ""
}

func checkMixedScript(input string, lim HeuristicLimits) (Match, bool) {
	scripts := map[string]int{}
	totalLetters := 0
	for _, r := range input {
		if !unicode.IsLetter(r) {
			continue
		}
		totalLetters++
		if s := runeScript(r); s != "" {
			scripts[s]++
		}
	}
	if totalLetters < lim.MixedScriptMinRunes {
		return Match{}, false
	}
	// Only flag when at least two different scripts exceed a small share
	// of the letter total — accidental loanwords (1-2 cyrillic letters
	// in a Latin sentence) shouldn't trip the heuristic.
	mixed := 0
	for _, c := range scripts {
		if float64(c)/float64(totalLetters) > 0.05 {
			mixed++
		}
	}
	if mixed < 2 {
		return Match{}, false
	}
	return Match{
		PatternID:      HeuristicMixedScript,
		Category:       CategoryLLM01,
		Description:    "mixed-script content (possible homoglyph attack)",
		AtlasTechnique: "AML.T0051.001",
		ByteRange:      [2]int{0, len(input)},
		Confidence:     0.55,
	}, true
}

// scanTokens walks whitespace-delimited tokens once, producing
// long-token, high-entropy, and token-flood matches in one pass.
func scanTokens(input string, lim HeuristicLimits) []Match {
	out := make([]Match, 0, 4)

	type tok struct {
		start, end int
		text       string
	}
	tokens := make([]tok, 0, 32)

	i := 0
	for i < len(input) {
		// Skip whitespace.
		for i < len(input) && isASCIISpace(input[i]) {
			i++
		}
		if i >= len(input) {
			break
		}
		start := i
		for i < len(input) && !isASCIISpace(input[i]) {
			i++
		}
		tokens = append(tokens, tok{start: start, end: i, text: input[start:i]})
	}

	for _, t := range tokens {
		tl := t.end - t.start
		if tl >= lim.LongTokenLen {
			out = append(out, Match{
				PatternID:      HeuristicLongToken,
				Category:       CategoryLLM01,
				Description:    "abnormally long single token",
				AtlasTechnique: "AML.T0051.001",
				ByteRange:      [2]int{t.start, t.end},
				Confidence:     0.5,
			})
		}
		if tl >= lim.HighEntropyMinLen {
			if h := shannonBitsPerByte(t.text); h >= lim.HighEntropyMinBits {
				out = append(out, Match{
					PatternID:      HeuristicHighEntropy,
					Category:       CategoryLLM01,
					Description:    "high-entropy chunk (likely encoded payload)",
					AtlasTechnique: "AML.T0051.001",
					ByteRange:      [2]int{t.start, t.end},
					Confidence:     0.55,
				})
			}
		}
	}

	// Token-flood: same token repeated >= TokenFloodMin times.
	if len(tokens) >= lim.TokenFloodMin {
		counts := map[string]int{}
		var floodTok string
		var floodN int
		for _, t := range tokens {
			counts[t.text]++
			if counts[t.text] > floodN {
				floodN = counts[t.text]
				floodTok = t.text
			}
		}
		if floodN >= lim.TokenFloodMin && len(floodTok) > 0 {
			out = append(out, Match{
				PatternID:      HeuristicTokenFlood,
				Category:       CategoryLLM04,
				Description:    "repeated-token flood (possible DoS)",
				AtlasTechnique: "AML.T0029",
				ByteRange:      [2]int{0, len(input)},
				Confidence:     0.45,
			})
		}
	}

	return out
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// shannonBitsPerByte computes Shannon entropy over the raw bytes of s.
// Bytes are the right unit because attackers use base64 / hex blobs
// where the encoded alphabet is the relevant signal.
func shannonBitsPerByte(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
