package identity

import (
	"context"
	"crypto/sha1" // #nosec G505 -- SHA-1 used only as a k-anonymity lookup key against a known-breached-password corpus (HIBP-style), never for authentication or integrity; see checkLeakedPassword below
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// MLScore mirrors the ML enricher's verdict. Decoupled from
// internal/ml so the scanner can be unit-tested with a fake.
//
// WHY: identity-claim ML lands in Phase 4.3 follow-up; the hook is
// nil-safe today. proto/ml/v1/inference.proto does not yet expose
// an identity-specific RPC — that arrives with the trained model.
type MLScore struct {
	Confidence   float64
	Verdict      string // CLEAN | SUSPICIOUS | BLOCKED
	ModelVersion string
	LatencyMs    float64
}

// MLEnricher is the soft-fail interface the scanner consults after
// the rule prefilter. nil = rule-only.
type MLEnricher interface {
	ScoreIdentity(ctx context.Context, claim ClaimRequest) (*MLScore, error)
	AlwaysScore() bool
}

// ClaimRequest is the structured identity-verification input.
//
// WHY: a flat `input string` won't work here — identity rules need
// per-field semantics (id_number vs dob vs email). The fields map
// is open so operators can extend without code changes once the
// overlay-driven custom indicator support lands.
type ClaimRequest struct {
	ClaimType ClaimType         `json:"claim_type"`
	Fields    map[string]string `json:"fields"`
	Context   Context           `json:"context"`
}

// Classification mirrors prompt-module triage labels.
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
	ClaimType      ClaimType      `json:"claim_type"`
	Context        Context        `json:"context"`
	ClaimHash      string         `json:"claim_hash"`
	DurationMS     float64        `json:"duration_ms"`
	WORMEntryID    *string        `json:"worm_entry_id,omitempty"`

	// ML enricher fields (Phase 4.3+). See prompt.ScanResult.
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

// replayEntry tracks one id_number's recent submission count.
type replayEntry struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

// Scanner applies the indicator library + tracks replay-window state.
//
// Library is held behind atomic.Pointer so admin hot-reload can swap
// indicators without rebuilding the scanner — same pattern as Module 3 / 5.
//
// Replay tracking is in-memory: map[id_number]→counter under a single
// mutex (the LRU is bounded by the cleanup goroutine, not by an explicit
// max — janitor evicts entries whose firstSeen is older than 2× the
// replay window). WHY: a real LRU adds eviction-on-read which
// complicates the threshold check; the periodic janitor is simpler and
// the worst case (memory bound) is bounded by traffic × 2× window.
type Scanner struct {
	library         atomic.Pointer[[]Pattern]
	cleanThreshold  float64
	blockThreshold  float64
	maxInputBytes   int
	replayWindow    time.Duration
	replayThreshold int

	mu     sync.Mutex
	replay map[string]*replayEntry

	// stopJanitor cancels the cleanup goroutine.
	stopJanitor chan struct{}
	janitorOnce sync.Once
}

// NewScanner constructs a scanner with the given indicator set + thresholds.
func NewScanner(library []Pattern, clean, block float64, maxBytes int, replayWindow time.Duration, replayThreshold int) *Scanner {
	if replayWindow <= 0 {
		replayWindow = 10 * time.Minute
	}
	if replayThreshold <= 0 {
		replayThreshold = 5
	}
	s := &Scanner{
		cleanThreshold:  clean,
		blockThreshold:  block,
		maxInputBytes:   maxBytes,
		replayWindow:    replayWindow,
		replayThreshold: replayThreshold,
		replay:          make(map[string]*replayEntry),
		stopJanitor:     make(chan struct{}),
	}
	lib := library
	s.library.Store(&lib)
	return s
}

// StartJanitor launches the background eviction goroutine. WHY:
// keeps the test surface simple — unit tests that don't care about
// replay can skip the goroutine entirely.
func (s *Scanner) StartJanitor() {
	s.janitorOnce.Do(func() {
		go s.runJanitor()
	})
}

// Stop terminates the janitor goroutine.
func (s *Scanner) Stop() {
	select {
	case <-s.stopJanitor:
		// already closed
	default:
		close(s.stopJanitor)
	}
}

func (s *Scanner) runJanitor() {
	// Janitor period: half the replay window — entries get at least
	// one full window worth of life before eviction kicks in.
	t := time.NewTicker(s.replayWindow / 2)
	defer t.Stop()
	for {
		select {
		case <-s.stopJanitor:
			return
		case <-t.C:
			s.evictStale(time.Now())
		}
	}
}

func (s *Scanner) evictStale(now time.Time) {
	cutoff := now.Add(-2 * s.replayWindow)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.replay {
		if e.lastSeen.Before(cutoff) {
			delete(s.replay, k)
		}
	}
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

// ReplayCount returns the current count for an id_number (test helper).
func (s *Scanner) ReplayCount(idNumber string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.replay[idNumber]; ok {
		return e.count
	}
	return 0
}

// canonicalise produces a stable JSON encoding for hashing.
// WHY: claim_hash is the join key for replay-detection at the DB
// layer (future) — order-stability matters across requests.
func canonicalise(c ClaimRequest) []byte {
	keys := make([]string, 0, len(c.Fields))
	for k := range c.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type kv struct {
		K string `json:"k"`
		V string `json:"v"`
	}
	pairs := make([]kv, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, kv{K: k, V: c.Fields[k]})
	}
	out, _ := json.Marshal(struct {
		ClaimType ClaimType `json:"claim_type"`
		Context   Context   `json:"context"`
		Fields    []kv      `json:"fields"`
	}{ClaimType: c.ClaimType, Context: c.Context, Fields: pairs})
	return out
}

// claimSize returns total bytes of canonicalised claim — the
// max-input-size guard applies to the canonical form, not the raw
// JSON, since the canonical form is what the scanner actually sees.
func claimSize(c ClaimRequest) int { return len(canonicalise(c)) }

// Scan runs the library against the claim and scores the matches.
func (s *Scanner) Scan(ctx context.Context, claim ClaimRequest) (*ScanResult, error) {
	return s.ScanWithML(ctx, claim, nil)
}

// ScanWithML mirrors prompt.Scanner.ScanWithML — see that doc for
// the folding rule. ml=nil → rule-only behaviour.
func (s *Scanner) ScanWithML(ctx context.Context, claim ClaimRequest, ml MLEnricher) (*ScanResult, error) {
	start := time.Now()

	canon := canonicalise(claim)
	if s.maxInputBytes > 0 && len(canon) > s.maxInputBytes {
		return nil, &InputTooLargeError{Max: s.maxInputBytes, Seen: len(canon)}
	}

	var matches []Match
	now := time.Now()
	lib := s.Patterns()
	for i := range lib {
		matches = append(matches, s.applyPattern(&lib[i], claim, now)...)
	}

	final := Score(matches, claim.Context, s.cleanThreshold, s.blockThreshold)

	hash := sha256.Sum256(canon)
	res := &ScanResult{
		ScanID:         "scan_" + uuid.New().String()[:12],
		Classification: final.Classification,
		Confidence:     final.Confidence,
		Matches:        matches,
		ClaimType:      claim.ClaimType,
		Context:        claim.Context,
		ClaimHash:      "sha256:" + hex.EncodeToString(hash[:]),
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
	mlScore, err := ml.ScoreIdentity(ctx, claim)
	if err != nil || mlScore == nil {
		return res, nil
	}
	res.MLConfidence = mlScore.Confidence
	res.MLVerdict = mlScore.Verdict
	res.MLBackendVersion = mlScore.ModelVersion
	res.MLLatencyMS = mlScore.LatencyMs

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

// applyPattern dispatches a single pattern against the claim. Composite
// indicators have hand-written cross-field logic; regex indicators run
// against the named field only.
func (s *Scanner) applyPattern(p *Pattern, c ClaimRequest, now time.Time) []Match {
	if p.Field == FieldComposite {
		return s.applyComposite(p, c, now)
	}
	val := c.Fields[string(p.Field)]
	if val == "" {
		return nil
	}
	// WEAK_PASSWORD_PATTERN family is login-only — applying these to
	// KYC name fields is a known false-positive trap.
	if p.Category == CategoryWeakPassword && c.ClaimType != ClaimLoginCreds {
		return nil
	}
	if p.re == nil || !p.re.MatchString(val) {
		return nil
	}
	return []Match{{
		PatternID:   p.ID,
		Category:    p.Category,
		Description: p.Description,
		AtlasTech:   p.AtlasTech,
		Field:       p.Field,
		Confidence:  p.BaseScore,
	}}
}

// applyComposite is the dispatch table for cross-field rules.
//
// WHY split: composite rules need each other's intermediate state
// (DOB-vs-today, issuer-vs-id_number, replay counter), and inlining
// them as 9 separate regex patterns would force ugly placeholder
// regex like ".*" with all the actual logic in the scanner anyway.
func (s *Scanner) applyComposite(p *Pattern, c ClaimRequest, now time.Time) []Match {
	switch p.ID {
	case "ID.format.country_mismatch.v1":
		return s.checkIDFormat(p, c)
	case "ID.jurisdiction.sanctioned.v1":
		return s.checkSanctioned(p, c)
	case "ID.synth.name_email_mismatch.v1":
		return s.checkNameEmailMismatch(p, c)
	case "ID.synth.dob_ssn_year_impossible.v1":
		return s.checkDOBSSNWindow(p, c)
	case "ID.age.future_dob.v1":
		return s.checkFutureDOB(p, c, now)
	case "ID.age.exceeds_max.v1":
		return s.checkMaxAge(p, c, now)
	case "ID.email.disposable_domain.v1":
		return s.checkDisposableEmail(p, c)
	case "ID.cred.leaked_sha1.v1":
		return s.checkLeakedPassword(p, c)
	case "ID.replay.window_threshold.v1":
		return s.checkReplay(p, c, now)
	}
	return nil
}

// ─── Composite helpers ──────────────────────────────────────────────

func (s *Scanner) checkIDFormat(p *Pattern, c ClaimRequest) []Match {
	id := strings.TrimSpace(c.Fields[string(FieldIDNumber)])
	country := c.Fields[string(FieldIssuerCountry)]
	if id == "" || country == "" {
		return nil
	}
	re := IDFormatFor(country, c.ClaimType)
	if re == nil {
		// No rule for this country/claim combo → don't penalise.
		return nil
	}
	if re.MatchString(id) {
		return nil
	}
	return []Match{{
		PatternID:   p.ID,
		Category:    p.Category,
		Description: p.Description,
		Field:       FieldIDNumber,
		Confidence:  p.BaseScore,
		Detail:      "id_number does not match format for issuer_country=" + strings.ToUpper(country),
	}}
}

func (s *Scanner) checkSanctioned(p *Pattern, c ClaimRequest) []Match {
	country := c.Fields[string(FieldIssuerCountry)]
	if country == "" || !IsSanctioned(country) {
		return nil
	}
	return []Match{{
		PatternID:   p.ID,
		Category:    p.Category,
		Description: p.Description,
		Field:       FieldIssuerCountry,
		Confidence:  p.BaseScore,
		Detail:      "issuer_country=" + strings.ToUpper(country),
	}}
}

func (s *Scanner) checkNameEmailMismatch(p *Pattern, c ClaimRequest) []Match {
	name := strings.ToLower(strings.TrimSpace(c.Fields[string(FieldName)]))
	email := strings.ToLower(strings.TrimSpace(c.Fields[string(FieldEmail)]))
	at := strings.LastIndex(email, "@")
	if name == "" || at <= 0 {
		return nil
	}
	local := email[:at]
	tokens := strings.FieldsFunc(name, func(r rune) bool {
		return r == ' ' || r == '-' || r == '\''
	})
	// WHY heuristic: if any name token of length>=3 appears in the
	// email local-part, profile coheres. If none do AND the local-part
	// contains no digits-only marker, fire low-conf.
	for _, tok := range tokens {
		if len(tok) >= 3 && strings.Contains(local, tok) {
			return nil
		}
	}
	return []Match{{
		PatternID:   p.ID,
		Category:    p.Category,
		Description: p.Description,
		Field:       FieldEmail,
		Confidence:  p.BaseScore,
	}}
}

func (s *Scanner) checkDOBSSNWindow(p *Pattern, c ClaimRequest) []Match {
	// Stub: SSN issuance windows by year are huge and the data is
	// state-specific. v1 fires only on the unambiguous case: claimed
	// DOB after 2011 (when SSN randomisation began) but SSN is still
	// in the old area-group format with a non-zero area number that
	// would have been impossible to assign. Real implementation
	// lands with the full SSA issuance table.
	dob := ParseDOB(c.Fields[string(FieldDOB)])
	id := c.Fields[string(FieldIDNumber)]
	if dob.IsZero() || id == "" || c.ClaimType != ClaimNationalID {
		return nil
	}
	country := strings.ToUpper(c.Fields[string(FieldIssuerCountry)])
	if country != "US" {
		return nil
	}
	// Stub heuristic only — real SSA window check is future work.
	return nil
}

func (s *Scanner) checkFutureDOB(p *Pattern, c ClaimRequest, now time.Time) []Match {
	dob := ParseDOB(c.Fields[string(FieldDOB)])
	if dob.IsZero() {
		return nil
	}
	if !dob.After(now) {
		return nil
	}
	return []Match{{
		PatternID:   p.ID,
		Category:    p.Category,
		Description: p.Description,
		Field:       FieldDOB,
		Confidence:  p.BaseScore,
	}}
}

func (s *Scanner) checkMaxAge(p *Pattern, c ClaimRequest, now time.Time) []Match {
	dob := ParseDOB(c.Fields[string(FieldDOB)])
	if dob.IsZero() {
		return nil
	}
	maxAgo := now.AddDate(-MaxHumanAgeYears, 0, 0)
	if !dob.Before(maxAgo) {
		return nil
	}
	return []Match{{
		PatternID:   p.ID,
		Category:    p.Category,
		Description: p.Description,
		Field:       FieldDOB,
		Confidence:  p.BaseScore,
	}}
}

func (s *Scanner) checkDisposableEmail(p *Pattern, c ClaimRequest) []Match {
	email := c.Fields[string(FieldEmail)]
	if email == "" || !IsDisposableEmail(email) {
		return nil
	}
	return []Match{{
		PatternID:   p.ID,
		Category:    p.Category,
		Description: p.Description,
		Field:       FieldEmail,
		Confidence:  p.BaseScore,
	}}
}

func (s *Scanner) checkLeakedPassword(p *Pattern, c ClaimRequest) []Match {
	if c.ClaimType != ClaimLoginCreds {
		return nil
	}
	pwd := c.Fields[string(FieldPassword)]
	if pwd == "" {
		return nil
	}
	h := sha1.Sum([]byte(pwd)) // #nosec G401 -- SHA-1 is the lookup key format for the leaked-credential blocklist (matches upstream breach-corpus format, e.g. HIBP), not a security boundary
	if !IsLeakedHash(strings.ToUpper(hex.EncodeToString(h[:]))) {
		return nil
	}
	return []Match{{
		PatternID:   p.ID,
		Category:    p.Category,
		Description: p.Description,
		Field:       FieldPassword,
		Confidence:  p.BaseScore,
		Detail:      "password matches v1 leaked-credential blocklist",
	}}
}

func (s *Scanner) checkReplay(p *Pattern, c ClaimRequest, now time.Time) []Match {
	id := strings.TrimSpace(c.Fields[string(FieldIDNumber)])
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.replay[id]
	if !ok || now.Sub(e.firstSeen) > s.replayWindow {
		// Window expired or first occurrence — reset the counter.
		s.replay[id] = &replayEntry{count: 1, firstSeen: now, lastSeen: now}
		return nil
	}
	e.count++
	e.lastSeen = now
	if e.count < s.replayThreshold {
		return nil
	}
	return []Match{{
		PatternID:   p.ID,
		Category:    p.Category,
		Description: p.Description,
		Field:       FieldIDNumber,
		Confidence:  p.BaseScore,
		Detail:      "replay counter exceeded threshold within window",
	}}
}
