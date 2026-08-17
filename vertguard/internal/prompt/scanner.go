package prompt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// MLErrorReporter is the optional sink the scanner notifies whenever
// the ML enricher returns an error or a nil score. The reporter MUST
// be safe for concurrent use. A nil reporter is allowed — the scanner
// falls back to silent soft-fail (the legacy behaviour).
//
// `backend` is the enricher's reported model version (or "unknown" when
// the call failed before a verdict was produced); `errClass` is a
// short, low-cardinality string classifying the failure (e.g. the
// error type name). The handler-side wiring deduplicates warn logs
// per (backend, errClass) so a flapping enricher doesn't flood logs.
type MLErrorReporter interface {
	ReportMLError(backend, errClass string, err error)
}

// errorClass produces a stable, low-cardinality label for err. Using
// the dynamic type name keeps the cardinality bounded — the alternative
// (err.Error()) would explode the metric label space.
func errorClass(err error) string {
	if err == nil {
		return "nil_score"
	}
	return fmt.Sprintf("%T", err)
}

// MLScore is the package-local mirror of the ML enricher's verdict.
// Decoupled from internal/ml so the scanner can be unit-tested with a
// fake enricher that has no gRPC dependency.
type MLScore struct {
	Confidence   float64
	Verdict      string // CLEAN | SUSPICIOUS | BLOCKED
	ModelVersion string
}

// MLEnricher is the soft-fail interface the scanner consults after the
// regex prefilter. nil is allowed — scanner falls back to regex-only.
type MLEnricher interface {
	// Score returns nil + error on failure. Errors are NEVER fatal; the
	// scanner logs and proceeds with regex-only verdict. AlwaysScore
	// reports the operator preference: when true, Scan calls Score on
	// every input regardless of regex verdict.
	Score(ctx context.Context, input, contextTag string) (*MLScore, error)
	AlwaysScore() bool
}

// Scanner applies a pattern library to user input.
// Stateless + safe for concurrent use.
//
// The library is held behind an atomic.Pointer so admin hot-reload can
// swap it without rebuilding the scanner or coordinating with in-flight
// Scans. Each Scan loads the snapshot once and iterates a stable slice.
type Scanner struct {
	library        atomic.Pointer[[]Pattern]
	cleanThreshold float64
	blockThreshold float64
	maxInputBytes  int

	// ML error observability — both optional. mlReporter receives every
	// ML failure (post-deduplication is the reporter's job for log
	// volume; the scanner reports unconditionally so counters stay
	// accurate). mlSeen tracks first-occurrence per (backend, errClass)
	// strictly for the warn-log dedup invoked by the default reporter.
	mlReporter atomic.Value // holds MLErrorReporter, may be nil
	mlSeen     sync.Map     // key: "backend|errClass" → struct{}

	// heuristicsEnabled toggles the token-level heuristics pass added in
	// VG-003. Defaults to true; tests that want pure-regex behaviour
	// flip it via DisableHeuristics().
	heuristicsEnabled bool
	heurLimits        HeuristicLimits
}

// EnableHeuristics turns the token-level pass on (the default).
func (s *Scanner) EnableHeuristics(lim HeuristicLimits) {
	s.heuristicsEnabled = true
	s.heurLimits = lim
}

// DisableHeuristics restores the regex-only behaviour. Mainly useful
// for legacy tests that hard-code expected match counts.
func (s *Scanner) DisableHeuristics() {
	s.heuristicsEnabled = false
}

// SetMLErrorReporter installs (or clears, with nil) the ML failure
// sink. Safe to call concurrently with Scan.
func (s *Scanner) SetMLErrorReporter(r MLErrorReporter) {
	if r == nil {
		s.mlReporter.Store((MLErrorReporter)(nil))
		return
	}
	s.mlReporter.Store(r)
}

// FirstMLError reports whether (backend, errClass) has been observed
// for the first time on this scanner. Used by reporters to gate
// warn-level logging without spamming on every failure of a flapping
// enricher.
func (s *Scanner) FirstMLError(backend, errClass string) bool {
	key := backend + "|" + errClass
	_, loaded := s.mlSeen.LoadOrStore(key, struct{}{})
	return !loaded
}

func (s *Scanner) reportMLError(backend, errClass string, err error) {
	v := s.mlReporter.Load()
	if v == nil {
		return
	}
	r, ok := v.(MLErrorReporter)
	if !ok || r == nil {
		return
	}
	r.ReportMLError(backend, errClass, err)
}

// NewScanner constructs a scanner with the given pattern library
// and classification thresholds.
func NewScanner(library []Pattern, clean, block float64, maxBytes int) *Scanner {
	s := &Scanner{
		cleanThreshold:    clean,
		blockThreshold:    block,
		maxInputBytes:     maxBytes,
		heuristicsEnabled: true,
		heurLimits:        DefaultHeuristicLimits,
	}
	lib := library
	s.library.Store(&lib)
	return s
}

// Patterns returns the current pattern snapshot. The returned slice
// must be treated as read-only — the scanner may continue to use it.
func (s *Scanner) Patterns() []Pattern {
	p := s.library.Load()
	if p == nil {
		return nil
	}
	return *p
}

// SetPatterns atomically replaces the active pattern library. Safe to
// call concurrently with Scan; in-flight Scans observe their pre-swap
// snapshot.
func (s *Scanner) SetPatterns(p []Pattern) {
	lib := p
	s.library.Store(&lib)
}

// Classification is the final scan outcome.
type Classification string

const (
	ClassificationClean      Classification = "CLEAN"
	ClassificationSuspicious Classification = "SUSPICIOUS"
	ClassificationBlocked    Classification = "BLOCKED"
)

// ScanResult is what the handler returns to the caller.
type ScanResult struct {
	ScanID         string         `json:"scan_id"`
	Classification Classification `json:"classification"`
	Confidence     float64        `json:"confidence"`
	Matches        []Match        `json:"matches"`
	InputHash      string         `json:"-"`
	InputLength    int            `json:"-"`
	DurationMS     float64        `json:"duration_ms"`
	WORMEntryID    *string        `json:"worm_entry_id,omitempty"`

	// ML enricher fields (Phase 4.2+). Populated only when an
	// MLEnricher was passed to ScanWithML and the call succeeded.
	MLConfidence     float64 `json:"ml_confidence,omitempty"`
	MLVerdict        string  `json:"ml_verdict,omitempty"`
	MLBackendVersion string  `json:"ml_backend_version,omitempty"`
}

// InputTooLargeError reports that the caller exceeded max_input_size.
type InputTooLargeError struct {
	Max  int
	Seen int
}

func (e *InputTooLargeError) Error() string {
	return "input exceeds maximum size"
}

// Scan runs the library against the input, scoring matches and
// producing a classification.
//
// Context boosts / degradations are applied in Score via the context
// string passed alongside; see scorer.go.
func (s *Scanner) Scan(input, contextTag string) (*ScanResult, error) {
	return s.ScanWithML(context.TODO(), input, contextTag, nil)
}

// ScanWithML is the ML-aware scan entry point. The regex prefilter is
// unchanged; ML is bolted on as a post-step that runs only on
// SUSPICIOUS verdicts (or on every input when ml.AlwaysScore() is
// true). Pass ml=nil for regex-only behaviour (the legacy path).
//
// Verdict-folding rule (mirrors phishing.Scanner — keep both in sync):
//
//   - regex CLEAN/BLOCKED + ML disabled-or-NotAlwaysScore → unchanged
//   - regex SUSPICIOUS + ML BLOCKED → BLOCKED (upgrade)
//   - regex SUSPICIOUS w/ confidence < 0.5 + ML CLEAN → CLEAN (downgrade)
//   - any other combination → keep regex verdict, record ML score for
//     observability (ml_confidence / ml_verdict surface in the JSON).
//
// ML errors are NEVER fatal — soft-fail by design.
func (s *Scanner) ScanWithML(ctx context.Context, input, contextTag string, ml MLEnricher) (*ScanResult, error) {
	start := time.Now()

	if s.maxInputBytes > 0 && len(input) > s.maxInputBytes {
		return nil, &InputTooLargeError{Max: s.maxInputBytes, Seen: len(input)}
	}

	lib := s.Patterns()
	// IMPORTANT: keep this as an explicit empty slice (not nil) so JSON
	// marshalling produces "[]" not "null". The OpenAPI contract for
	// ScanResult.matches is `array`, and clients (incl. the dashboard)
	// trip on null. See TestScanner_BenignInput_MatchesIsEmptyArray.
	matches := make([]Match, 0)
	for i := range lib {
		matches = append(matches, lib[i].Scan(input)...)
	}
	if s.heuristicsEnabled {
		matches = append(matches, RunHeuristics(input, s.heurLimits)...)
	}

	final := Score(matches, contextTag, s.cleanThreshold, s.blockThreshold)
	hash := sha256.Sum256([]byte(input))

	res := &ScanResult{
		ScanID:         "scan_" + uuid.New().String()[:12],
		Classification: final.Classification,
		Confidence:     final.Confidence,
		Matches:        matches,
		InputHash:      "sha256:" + hex.EncodeToString(hash[:]),
		InputLength:    len(input),
		DurationMS:     float64(time.Since(start).Microseconds()) / 1000.0,
	}

	// ML post-step. Skip when no enricher, or when verdict isn't
	// SUSPICIOUS and operator hasn't opted into AlwaysScore.
	if ml == nil {
		return res, nil
	}
	if final.Classification != ClassificationSuspicious && !ml.AlwaysScore() {
		return res, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	mlScore, err := ml.Score(ctx, input, contextTag)
	if err != nil || mlScore == nil {
		// Soft-fail: regex verdict already in res. Surface to the
		// reporter so the prompt_ml_errors_total counter increments
		// and the wiring side can warn-log first occurrences.
		backend := "unknown"
		if mlScore != nil && mlScore.ModelVersion != "" {
			backend = mlScore.ModelVersion
		}
		s.reportMLError(backend, errorClass(err), err)
		return res, nil
	}
	res.MLConfidence = mlScore.Confidence
	res.MLVerdict = mlScore.Verdict
	res.MLBackendVersion = mlScore.ModelVersion

	// Verdict folding — see method doc for the rule.
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
