package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/vertguard/internal/api"
	"github.com/opensecstack/vertguard/internal/api/handlers"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/metrics"
	"github.com/opensecstack/vertguard/internal/phishing"
	"github.com/opensecstack/vertguard/internal/prompt"
	"github.com/rs/zerolog"
)

// setupPhishingServer returns a testEnv with the phishing handler wired in
// alongside the standard prompt + threatfeed handlers. devMode controls
// whether JWT auth is enforced.
func setupPhishingServer(t *testing.T, devMode bool) *testEnv {
	t.Helper()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         0,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Auth: config.AuthConfig{
			Secret:  testSecret,
			Issuer:  testIssuer,
			DevMode: devMode,
		},
		Prompt: config.PromptConfig{
			CleanThreshold: 0.30,
			BlockThreshold: 0.70,
			MaxInputSize:   1024 * 1024,
		},
		Phishing: config.PhishingConfig{
			Enabled:        true,
			CleanThreshold: 0.30,
			BlockThreshold: 0.70,
			MaxInputSize:   1024 * 1024,
		},
	}

	mreg := metrics.New()

	promptScanner := prompt.NewScanner(
		prompt.DefaultLibrary,
		cfg.Prompt.CleanThreshold,
		cfg.Prompt.BlockThreshold,
		int(cfg.Prompt.MaxInputSize),
	)
	promptH := handlers.NewPromptHandler(
		promptScanner, nil, metrics.NewPromptMetricsAdapter(mreg),
	)

	phishingScanner := phishing.NewScanner(
		phishing.DefaultLibrary,
		cfg.Phishing.CleanThreshold,
		cfg.Phishing.BlockThreshold,
		int(cfg.Phishing.MaxInputSize),
	)
	phishingH := handlers.NewPhishingHandler(
		phishingScanner, nil, metrics.NewPhishingMetricsAdapter(mreg),
	)

	threatFeedH := handlers.NewThreatFeedHandler()
	verifier := auth.NewVerifier(cfg.Auth.Secret, cfg.Auth.Issuer)
	logger := zerolog.Nop()

	apiSrv := api.New(api.Options{
		Config:        cfg,
		Logger:        &logger,
		Pinger:        stubPinger{},
		Prompt:        promptH,
		Phishing:      phishingH,
		ThreatFeed:    threatFeedH,
		Metrics:       mreg,
		Authenticator: verifier,
	})

	httpSrv := httptest.NewServer(apiSrv.Handler())
	return &testEnv{
		srv:     httpSrv,
		mreg:    mreg,
		cleanup: httpSrv.Close,
	}
}

// ── helpers ──────────────────────────────────────────────────────────────

// decodePhishingResult decodes the response body into a phishing.ScanResult
// and fails the test on any error.
func decodePhishingResult(t *testing.T, resp *http.Response) phishing.ScanResult {
	t.Helper()
	var result phishing.ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode phishing response: %v", err)
	}
	return result
}

// ── tests ─────────────────────────────────────────────────────────────────

// TestPhishing_ValidURL_Returns200WithVerdict confirms that a well-formed,
// non-suspicious URL scans successfully and the response carries the verdict
// fields mandated by the API contract.
func TestPhishing_ValidURL_Returns200WithVerdict(t *testing.T) {
	env := setupPhishingServer(t, true /* devMode — no JWT required */)
	defer env.cleanup()

	body := `{"input":"https://www.example.com/","kind":"url"}`
	resp := doRequest(t, env, http.MethodPost, "/api/v1/phishing/scan", "", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	result := decodePhishingResult(t, resp)

	if result.ScanID == "" {
		t.Fatal("expected non-empty scan_id in response")
	}
	if result.Classification == "" {
		t.Fatal("expected non-empty classification in response")
	}
}

// TestPhishing_ValidEmail_Returns200WithVerdict confirms that an email-kind
// input is accepted and the scanner returns a verdict.
func TestPhishing_ValidEmail_Returns200WithVerdict(t *testing.T) {
	env := setupPhishingServer(t, true)
	defer env.cleanup()

	body := `{"input":"Hello, please review the attached quarterly report at your convenience.","kind":"email"}`
	resp := doRequest(t, env, http.MethodPost, "/api/v1/phishing/scan", "", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	result := decodePhishingResult(t, resp)

	if result.ScanID == "" {
		t.Fatal("expected non-empty scan_id in response")
	}
	if result.Kind != phishing.KindEmail {
		t.Fatalf("kind = %q, want %q", result.Kind, phishing.KindEmail)
	}
	if result.Classification == "" {
		t.Fatal("expected non-empty classification in response")
	}
}

// TestPhishing_EmptyBody_Returns400 confirms that sending an empty JSON
// object (missing input field) produces a 400 Bad Request.
func TestPhishing_EmptyBody_Returns400(t *testing.T) {
	env := setupPhishingServer(t, true)
	defer env.cleanup()

	resp := doRequest(t, env, http.MethodPost, "/api/v1/phishing/scan", "", `{"input":""}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// TestPhishing_MissingBody_Returns400 confirms that a malformed / missing
// JSON body is rejected with 400.
func TestPhishing_MissingBody_Returns400(t *testing.T) {
	env := setupPhishingServer(t, true)
	defer env.cleanup()

	// Send no body at all — the decoder should return an error.
	resp := doRequest(t, env, http.MethodPost, "/api/v1/phishing/scan", "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// TestPhishing_NoToken_Returns401 confirms that a request without a JWT is
// rejected with 401 when auth is enforced (devMode=false).
func TestPhishing_NoToken_Returns401(t *testing.T) {
	env := setupPhishingServer(t, false /* auth enforced */)
	defer env.cleanup()

	body := `{"input":"https://www.example.com/","kind":"url"}`
	resp := doRequest(t, env, http.MethodPost, "/api/v1/phishing/scan", "" /* no token */, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestPhishing_HighConfidenceURL_IsPhishing verifies that a URL carrying the
// userinfo-@ obfuscation pattern (PH.url.userinfo_at.v1, base score 0.9) is
// classified as BLOCKED and the response confidence is >= 0.9.
//
// Scoring walkthrough:
//
//	PH.url.userinfo_at.v1 fires  →  base 0.90
//	URL_OBFUSCATION category boost →  + 0.10
//	PH.tld.suspicious.v1 also fires (.xyz) → multi-match boost + 0.05
//	Final (clamped) ≥ 1.0  →  BLOCKED (threshold 0.70)
func TestPhishing_HighConfidenceURL_IsPhishing(t *testing.T) {
	env := setupPhishingServer(t, true)
	defer env.cleanup()

	// This URL triggers PH.url.userinfo_at.v1 (userinfo confusion via @)
	// and PH.tld.suspicious.v1 (.xyz TLD), producing a high aggregate score.
	phishingURL := `http://attacker@malicious-login.xyz/secure`
	body := `{"input":"` + phishingURL + `","kind":"url"}`

	resp := doRequest(t, env, http.MethodPost, "/api/v1/phishing/scan", "", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	result := decodePhishingResult(t, resp)

	if result.Classification != phishing.ClassificationBlocked {
		t.Fatalf("classification = %q, want %q (confidence=%.3f, matches=%d)",
			result.Classification, phishing.ClassificationBlocked,
			result.Confidence, len(result.Matches))
	}
	if result.Confidence < 0.9 {
		t.Fatalf("confidence = %.3f, want >= 0.9", result.Confidence)
	}
	if len(result.Matches) == 0 {
		t.Fatal("expected at least one indicator match for phishing URL")
	}
}

// TestPhishing_AuthenticatedOperator_CanScan confirms that a valid operator
// JWT is accepted and the scan proceeds normally under auth enforcement.
func TestPhishing_AuthenticatedOperator_CanScan(t *testing.T) {
	env := setupPhishingServer(t, false /* auth enforced */)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	body := `{"input":"https://www.example.com/","kind":"url"}`
	resp := doRequest(t, env, http.MethodPost, "/api/v1/phishing/scan", tok, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("operator status = %d, want 200", resp.StatusCode)
	}
}
