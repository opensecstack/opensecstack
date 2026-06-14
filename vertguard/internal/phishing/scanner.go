package phishing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// MLScore mirrors the ML enricher's verdict for the phishing scanner.
type MLScore struct {
	Confidence   float64
	Verdict      string // CLEAN | SUSPICIOUS | BLOCKED
	ModelVersion string
}

// MLEnricher is the soft-fail interface the phishing scanner consults
// after the indicator prefilter. nil = regex-only.
type MLEnricher interface {
	ScorePhishing(ctx context.Context, input, kind string) (*MLScore, error)
	AlwaysScore() bool
}

// brandHostRe extracts host and brand-in-path for the path_spoof
// suppression filter. Mirrors PH.brand.path_spoof.v1 capture groups.
var brandHostRe = regexp.MustCompile(
	`(?i)https?://([^\s/]+)/[^\s]*?\b(paypal|microsoft|google|apple|amazon|facebook|netflix|chase|wellsfargo|bankofamerica)/(?:login|signin|verify|account)\b`,
)

// Kind narrows scoring to the input modality. Mail bodies get a
// credential-harvest boost since same-text on a chat input is far
// less load-bearing.
type Kind string

const (
	KindURL   Kind = "url"
	KindEmail Kind = "email"
	KindHTML  Kind = "html"
)

// Scanner applies the indicator library. Stateless + concurrent-safe.
//
// The library is held behind atomic.Pointer so admin hot-reload can
// swap indicators without rebuilding the scanner.
type Scanner struct {
	library        atomic.Pointer[[]Pattern]
	cleanThreshold float64
	blockThreshold float64
	maxInputBytes  int
}

// NewScanner constructs a scanner with the given indicator set + thresholds.
func NewScanner(library []Pattern, clean, block float64, maxBytes int) *Scanner {
	s := &Scanner{
		cleanThreshold: clean,
		blockThreshold: block,
		maxInputBytes:  maxBytes,
	}
	lib := library
	s.library.Store(&lib)
	return s
}

// Patterns returns the active indicator snapshot (read-only).
func (s *Scanner) Patterns() []Pattern {
	p := s.library.Load()
	if p == nil {
		return nil
	}
	return *p
}

// SetPatterns atomically replaces the active indicator set.
func (s *Scanner) SetPatterns(p []Pattern) {
	lib := p
	s.library.Store(&lib)
}

// Classification mirrors prompt-module triage labels for ecosystem consistency.
type Classification string

const (
	ClassificationClean      Classification = "CLEAN"
	ClassificationSuspicious Classification = "SUSPICIOUS"
	ClassificationBlocked    Classification = "BLOCKED"
)

// ScanResult is the handler-shaped scan outcome.
type ScanResult struct {
	ScanID         string         `json:"scan_id"`
	Classification Classification `json:"classification"`
	Confidence     float64        `json:"confidence"`
	Matches        []Match        `json:"matches"`
	Kind           Kind           `json:"kind"`
	InputHash      string         `json:"-"`
	InputLength    int            `json:"-"`
	DurationMS     float64        `json:"duration_ms"`
	WORMEntryID    *string        `json:"worm_entry_id,omitempty"`

	// ML enrichment fields — populated when ML service is available (Phase 4.2+).
	MLConfidence     float64 `json:"ml_confidence,omitempty"`
	MLVerdict        string  `json:"ml_verdict,omitempty"`
	MLBackendVersion string  `json:"ml_backend_version,omitempty"`
	MLLatencyMS      float64 `json:"ml_latency_ms,omitempty"`
}

// InputTooLargeError reports caller exceeded max_input_size.
type InputTooLargeError struct {
	Max  int
	Seen int
}

func (e *InputTooLargeError) Error() string { return "input exceeds maximum size" }

// suppressBrandPathFP drops PH.brand.path_spoof.v1 hits where the host
// itself is the legitimate brand (RE2 has no negative lookahead, so we
// post-filter what would otherwise be a regex-side host check).
func suppressBrandPathFP(input string, matches []Match) []Match {
	if len(matches) == 0 {
		return matches
	}
	subs := brandHostRe.FindAllStringSubmatch(input, -1)
	if len(subs) == 0 {
		return matches
	}
	// Build a set of (host, brand) pairs where host already contains the brand.
	hostMatchesBrand := false
	for _, sub := range subs {
		if len(sub) < 3 {
			continue
		}
		host := strings.ToLower(sub[1])
		brand := strings.ToLower(sub[2])
		// Strip port and userinfo for the host-vs-brand check.
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		if colon := strings.Index(host, ":"); colon >= 0 {
			host = host[:colon]
		}
		if strings.Contains(host, brand+".") || strings.HasSuffix(host, "."+brand+".com") {
			hostMatchesBrand = true
			break
		}
	}
	if !hostMatchesBrand {
		return matches
	}
	out := matches[:0]
	for _, m := range matches {
		if m.PatternID == "PH.brand.path_spoof.v1" {
			continue
		}
		out = append(out, m)
	}
	return out
}

// Scan runs the library against input and scores the matches.
//
// kind selects scoring context (email gets a harvest boost). Defaults
// to KindURL when blank to preserve safety on missing field.
func (s *Scanner) Scan(input string, kind Kind) (*ScanResult, error) {
	return s.ScanWithML(nil, input, kind, nil)
}

// ScanWithML mirrors prompt.Scanner.ScanWithML — see that doc for the
// folding rule. ml=nil → regex-only behaviour.
func (s *Scanner) ScanWithML(ctx context.Context, input string, kind Kind, ml MLEnricher) (*ScanResult, error) {
	start := time.Now()

	if s.maxInputBytes > 0 && len(input) > s.maxInputBytes {
		return nil, &InputTooLargeError{Max: s.maxInputBytes, Seen: len(input)}
	}
	if kind == "" {
		kind = KindURL
	}

	lib := s.Patterns()
	var matches []Match
	for i := range lib {
		matches = append(matches, lib[i].Scan(input)...)
	}
	matches = suppressBrandPathFP(input, matches)

	final := Score(matches, kind, s.cleanThreshold, s.blockThreshold)
	hash := sha256.Sum256([]byte(input))

	res := &ScanResult{
		ScanID:         "scan_" + uuid.New().String()[:12],
		Classification: final.Classification,
		Confidence:     final.Confidence,
		Matches:        matches,
		Kind:           kind,
		InputHash:      "sha256:" + hex.EncodeToString(hash[:]),
		InputLength:    len(input),
		DurationMS:     float64(time.Since(start).Microseconds()) / 1000.0,
	}

	if ml == nil {
		return res, nil
	}
	if final.Classification != ClassificationSuspicious && !ml.AlwaysScore() {
		return res, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	mlScore, err := ml.ScorePhishing(ctx, input, string(kind))
	if err != nil || mlScore == nil {
		return res, nil
	}
	res.MLConfidence = mlScore.Confidence
	res.MLVerdict = mlScore.Verdict
	res.MLBackendVersion = mlScore.ModelVersion

	switch mlScore.Verdict {
	case "BLOCKED":
		if final.Classification == ClassificationSuspicious {
			res.Classification = ClassificationBlocked
		}
	case "CLEAN":
		if final.Classification == ClassificationSuspicious && final.Confidence < 0.5 {
			res.Classification = ClassificationClean
		}
	}
	return res, nil
}
