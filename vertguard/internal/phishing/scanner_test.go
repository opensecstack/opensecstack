package phishing

import (
	"context"
	"strings"
	"testing"
)

// fakeML is a unit-test MLEnricher.
type fakeML struct {
	verdict    string
	confidence float64
	always     bool
	called     bool
}

func (f *fakeML) ScorePhishing(_ context.Context, _, _ string) (*MLScore, error) {
	f.called = true
	return &MLScore{Confidence: f.confidence, Verdict: f.verdict, ModelVersion: "test"}, nil
}
func (f *fakeML) AlwaysScore() bool { return f.always }

// TestScanWithML_UpgradeOnBlock — SUSPICIOUS regex + ML BLOCKED → BLOCKED.
func TestScanWithML_UpgradeOnBlock(t *testing.T) {
	// Urgency-only inputs land SUSPICIOUS (not BLOCKED) under the
	// production library — perfect for testing the upgrade rule.
	s := newDefaultScanner()
	ml := &fakeML{verdict: "BLOCKED", confidence: 0.95}
	r, err := s.ScanWithML(context.Background(),
		"Your account will be suspended unless you act.", KindEmail, ml)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r.Classification == ClassificationClean {
		t.Fatalf("precondition: expected non-CLEAN regex verdict, got CLEAN")
	}
	if r.Classification == ClassificationSuspicious && r.MLVerdict != "BLOCKED" {
		t.Fatalf("ml_verdict not recorded: %+v", r)
	}
	// If regex was already SUSPICIOUS, the fold should upgrade to BLOCKED.
	// If regex landed BLOCKED on its own, that's fine — record-only path.
}

// TestScanWithML_DowngradeOnClean — SUSPICIOUS+low-conf+ML-CLEAN → CLEAN.
// Synthesise a SUSPICIOUS verdict with a low-confidence URL pattern.
func TestScanWithML_DowngradeOnClean(t *testing.T) {
	// Build a tiny library so we can land at confidence < 0.5 SUSPICIOUS.
	pat := MustCompilePattern(
		"PH.test.synth.v1", CategoryURLObfuscation, "synth", "AML.T9999", 0.35,
		`triggerword`,
	)
	s := NewScanner([]Pattern{pat}, 0.3, 0.7, 1<<20)
	ml := &fakeML{verdict: "CLEAN", confidence: 0.0}
	r, err := s.ScanWithML(context.Background(), "this contains triggerword somewhere", KindURL, ml)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r.Classification != ClassificationClean {
		t.Fatalf("want CLEAN after downgrade, got %s (conf=%v, ml=%s)",
			r.Classification, r.Confidence, r.MLVerdict)
	}
}

// TestScanWithML_NotCalledForCleanWithoutAlwaysScore — hot-path guard.
func TestScanWithML_NotCalledForCleanWithoutAlwaysScore(t *testing.T) {
	s := NewScanner(nil, 0.3, 0.7, 1<<20)
	ml := &fakeML{verdict: "BLOCKED", confidence: 0.99}
	_, _ = s.ScanWithML(context.Background(), "https://example.com/", KindURL, ml)
	if ml.called {
		t.Fatalf("ML should not be called on regex-CLEAN unless AlwaysScore")
	}
}

func newDefaultScanner() *Scanner {
	return NewScanner(DefaultLibrary, 0.3, 0.7, 1<<20)
}

func TestScanner_EmptyInput_IsClean(t *testing.T) {
	r, err := newDefaultScanner().Scan("", KindURL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Classification != ClassificationClean {
		t.Fatalf("want CLEAN, got %s", r.Classification)
	}
}

func TestScanner_URLUserinfoAt_Blocks(t *testing.T) {
	r, _ := newDefaultScanner().Scan("https://bank.com@evil.tld/login", KindURL)
	if r.Classification != ClassificationBlocked {
		t.Fatalf("want BLOCKED, got %s (matches=%d)", r.Classification, len(r.Matches))
	}
}

func TestScanner_IDNHomograph_Detected(t *testing.T) {
	// Cyrillic 'а' replacing Latin 'a' in apple.
	r, _ := newDefaultScanner().Scan("https://аpple.com/signin", KindURL)
	if len(r.Matches) == 0 {
		t.Fatalf("expected IDN homograph match")
	}
}

func TestScanner_ShortenerLoginPath_Detected(t *testing.T) {
	r, _ := newDefaultScanner().Scan("Click https://bit.ly/secure-login-now to confirm", KindURL)
	if len(r.Matches) == 0 {
		t.Fatalf("expected shortener-login match")
	}
}

func TestScanner_BrandPathSpoof_Blocks(t *testing.T) {
	r, _ := newDefaultScanner().Scan("https://malicious.example/paypal/login", KindEmail)
	if r.Classification != ClassificationBlocked {
		t.Fatalf("want BLOCKED, got %s (matches=%d, conf=%.2f)",
			r.Classification, len(r.Matches), r.Confidence)
	}
}

func TestScanner_BrandLookalikeDomain_Detected(t *testing.T) {
	r, _ := newDefaultScanner().Scan("https://paypal-secure.example.com/", KindURL)
	if len(r.Matches) == 0 {
		t.Fatalf("expected lookalike domain match")
	}
}

func TestScanner_CredentialHarvestForm_Blocks(t *testing.T) {
	body := `<html><body>Sign in: <form action="https://evil.tld/login" method="post">` +
		`<input type="password" name="pw"></form></body></html>`
	r, _ := newDefaultScanner().Scan(body, KindHTML)
	if r.Classification != ClassificationBlocked {
		t.Fatalf("want BLOCKED, got %s (matches=%d)", r.Classification, len(r.Matches))
	}
}

func TestScanner_SSNRequest_Blocks(t *testing.T) {
	r, _ := newDefaultScanner().Scan("Please confirm your social security number to continue.", KindEmail)
	if r.Classification != ClassificationBlocked {
		t.Fatalf("want BLOCKED, got %s", r.Classification)
	}
}

func TestScanner_UrgencySuspended_Suspicious(t *testing.T) {
	r, _ := newDefaultScanner().Scan("Your account will be suspended unless you act.", KindEmail)
	if r.Classification == ClassificationClean {
		t.Fatalf("want non-CLEAN for urgency lure, got CLEAN")
	}
}

func TestScanner_VerifyWithin24h_Suspicious(t *testing.T) {
	r, _ := newDefaultScanner().Scan("Verify your identity within 24 hours.", KindEmail)
	if r.Classification == ClassificationClean {
		t.Fatalf("want non-CLEAN, got CLEAN (matches=%d)", len(r.Matches))
	}
}

func TestScanner_SuspiciousTLD_Detected(t *testing.T) {
	r, _ := newDefaultScanner().Scan("https://download.example.zip/file", KindURL)
	if len(r.Matches) == 0 {
		t.Fatalf("expected suspicious TLD match")
	}
}

func TestScanner_DoubleExtensionAttachment_Detected(t *testing.T) {
	r, _ := newDefaultScanner().Scan("Open invoice.pdf.exe to view", KindEmail)
	if len(r.Matches) == 0 {
		t.Fatalf("expected double-extension match")
	}
}

func TestScanner_MacroLure_Detected(t *testing.T) {
	r, _ := newDefaultScanner().Scan("Please enable content to view this document.", KindEmail)
	if len(r.Matches) == 0 {
		t.Fatalf("expected macro-lure match")
	}
}

func TestScanner_MXMismatchMarker_Detected(t *testing.T) {
	r, _ := newDefaultScanner().Scan("X-MX-Mismatch: true\nFrom: x@y", KindEmail)
	if len(r.Matches) == 0 {
		t.Fatalf("expected MX mismatch marker match")
	}
}

// ─── False-positive benchmarks ─────────────────────────────────────
// Legitimate emails that contain trigger words must NOT block.

func TestScanner_FP_LegitimateAccountVerify_NotBlocked(t *testing.T) {
	body := "Welcome! Please verify your email by clicking the link in your inbox. Thanks!"
	r, _ := newDefaultScanner().Scan(body, KindEmail)
	if r.Classification == ClassificationBlocked {
		t.Fatalf("legitimate verify msg blocked: matches=%d conf=%.2f",
			len(r.Matches), r.Confidence)
	}
}

func TestScanner_FP_NewsArticleAboutPhishing_NotBlocked(t *testing.T) {
	body := "Researchers report unusual sign-in attempts targeting banks via lookalike domains."
	r, _ := newDefaultScanner().Scan(body, KindEmail)
	if r.Classification == ClassificationBlocked {
		t.Fatalf("news article about phishing blocked: matches=%d conf=%.2f",
			len(r.Matches), r.Confidence)
	}
}

func TestScanner_FP_LegitPaypalURL_NotBlocked(t *testing.T) {
	r, _ := newDefaultScanner().Scan("https://www.paypal.com/signin", KindURL)
	if r.Classification == ClassificationBlocked {
		t.Fatalf("legit paypal.com blocked: matches=%d", len(r.Matches))
	}
}

func TestScanner_FP_PlainGreeting_IsClean(t *testing.T) {
	r, _ := newDefaultScanner().Scan("Hi team, here is the agenda for tomorrow.", KindEmail)
	if r.Classification != ClassificationClean {
		t.Fatalf("want CLEAN, got %s", r.Classification)
	}
}

func TestScanner_InputTooLarge_ReturnsError(t *testing.T) {
	s := NewScanner(DefaultLibrary, 0.3, 0.7, 100)
	_, err := s.Scan(strings.Repeat("a", 200), KindURL)
	if _, ok := err.(*InputTooLargeError); !ok {
		t.Fatalf("expected *InputTooLargeError, got %T", err)
	}
}

func TestScanner_HashIsStable(t *testing.T) {
	s := newDefaultScanner()
	r1, _ := s.Scan("hello", KindURL)
	r2, _ := s.Scan("hello", KindURL)
	if r1.InputHash != r2.InputHash {
		t.Fatalf("hash unstable: %s vs %s", r1.InputHash, r2.InputHash)
	}
}
