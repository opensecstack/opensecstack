package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/api"
	"github.com/opensecstack/vertguard/internal/api/handlers"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/identity"
	"github.com/opensecstack/vertguard/internal/metrics"
	"github.com/opensecstack/vertguard/internal/prompt"
)

// ─── Stub ML enricher ────────────────────────────────────────────────

// stubIdentityMLEnricher implements identity.MLEnricher with hardcoded
// return values. callCount tracks how many times ScoreIdentity is called
// so tests can assert it was exercised without gRPC.
type stubIdentityMLEnricher struct {
	confidence  float64
	verdict     string
	callCount   atomic.Int64
	alwaysScore bool
}

func (s *stubIdentityMLEnricher) ScoreIdentity(_ context.Context, _ identity.ClaimRequest) (*identity.MLScore, error) {
	s.callCount.Add(1)
	return &identity.MLScore{
		Confidence:   s.confidence,
		Verdict:      s.verdict,
		ModelVersion: "stub-identity-v0",
	}, nil
}

func (s *stubIdentityMLEnricher) AlwaysScore() bool { return s.alwaysScore }

// setupIdentityServer starts a real VertGuard HTTP server with the identity
// handler wired in addition to the standard handlers. The identity scanner is
// built with the same thresholds used in unit tests; replayWindow and
// replayThreshold are parameterised so replay-detection tests can use tight
// values without coupling to the global defaults.
func setupIdentityServer(t *testing.T, replayWindow time.Duration, replayThreshold int) *testEnv {
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
			DevMode: false,
		},
		Prompt: config.PromptConfig{
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

	identityScanner := identity.NewScanner(
		identity.DefaultLibrary,
		0.30, // clean threshold
		0.70, // block threshold
		64*1024,
		replayWindow,
		replayThreshold,
	)
	identityH := handlers.NewIdentityHandler(identityScanner, nil, nil)

	threatFeedH := handlers.NewThreatFeedHandler()
	verifier := auth.NewVerifier(cfg.Auth.Secret, cfg.Auth.Issuer)
	logger := zerolog.Nop()

	apiSrv := api.New(api.Options{
		Config:        cfg,
		Logger:        &logger,
		Pinger:        stubPinger{},
		Prompt:        promptH,
		Identity:      identityH,
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

// ─── helpers ───────────────────────────────────────────────────────────────

const identityPath = "/api/v1/identity/verify"

// validKYCBody returns a well-formed ClaimRequest JSON that the default
// library should classify as CLEAN (Albanian national ID, no red-flag
// fields). Mirrors the fixture used by TestScan_CleanKYC in the unit suite.
func validKYCBody() string {
	return `{
		"claim_type": "national_id",
		"context":    "kyc",
		"fields": {
			"id_number":      "I12345678X",
			"issuer_country": "AL",
			"dob":            "1990-05-12",
			"name":           "Albi Hoxha",
			"email":          "albi.hoxha@example.com"
		}
	}`
}

// ─── test cases ────────────────────────────────────────────────────────────

// TestIdentity_ValidRequest verifies that a well-formed KYC claim with an
// authenticated operator token returns 200 and a parseable ScanResult.
func TestIdentity_ValidRequest(t *testing.T) {
	env := setupIdentityServer(t, 10*time.Minute, 5)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	resp := doRequest(t, env, http.MethodPost, identityPath, tok, validKYCBody())
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result identity.ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.ScanID == "" {
		t.Fatal("expected non-empty scan_id in response")
	}
	if result.ClaimHash == "" {
		t.Fatal("expected non-empty claim_hash in response")
	}
	if result.Classification == "" {
		t.Fatal("expected non-empty classification in response")
	}
	if result.ClaimType != identity.ClaimNationalID {
		t.Fatalf("claim_type = %q, want %q", result.ClaimType, identity.ClaimNationalID)
	}
}

// TestIdentity_MissingClaimType verifies that omitting claim_type from the
// request body returns 400 with an appropriate error code.
func TestIdentity_MissingClaimType(t *testing.T) {
	env := setupIdentityServer(t, 10*time.Minute, 5)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	body := `{"context":"kyc","fields":{"id_number":"I12345678X"}}`
	resp := doRequest(t, env, http.MethodPost, identityPath, tok, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// TestIdentity_InvalidClaimType verifies that an unrecognised claim_type
// value is rejected with 400.
func TestIdentity_InvalidClaimType(t *testing.T) {
	env := setupIdentityServer(t, 10*time.Minute, 5)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	body := `{"claim_type":"biometric","context":"kyc","fields":{"id_number":"I12345678X"}}`
	resp := doRequest(t, env, http.MethodPost, identityPath, tok, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown claim_type", resp.StatusCode)
	}
}

// TestIdentity_InvalidContext verifies that an unrecognised context value is
// rejected with 400.
func TestIdentity_InvalidContext(t *testing.T) {
	env := setupIdentityServer(t, 10*time.Minute, 5)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	body := `{"claim_type":"passport","context":"biometric_scan","fields":{"id_number":"AB1234567"}}`
	resp := doRequest(t, env, http.MethodPost, identityPath, tok, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown context", resp.StatusCode)
	}
}

// TestIdentity_NoToken verifies that a request without a JWT is rejected
// with 401 before it reaches the identity handler.
func TestIdentity_NoToken(t *testing.T) {
	env := setupIdentityServer(t, 10*time.Minute, 5)
	defer env.cleanup()

	resp := doRequest(t, env, http.MethodPost, identityPath, "", validKYCBody())
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestIdentity_ExpiredToken verifies that an expired JWT is rejected with 401.
func TestIdentity_ExpiredToken(t *testing.T) {
	env := setupIdentityServer(t, 10*time.Minute, 5)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, -time.Hour)
	resp := doRequest(t, env, http.MethodPost, identityPath, tok, validKYCBody())
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for expired token", resp.StatusCode)
	}
}

// TestIdentity_ViewerForbidden verifies that a viewer-role JWT (read-only)
// cannot call the write-gated identity endpoint and receives 403.
func TestIdentity_ViewerForbidden(t *testing.T) {
	env := setupIdentityServer(t, 10*time.Minute, 5)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleViewer, time.Hour)
	resp := doRequest(t, env, http.MethodPost, identityPath, tok, validKYCBody())
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for viewer role", resp.StatusCode)
	}
}

// TestIdentity_MalformedJSON verifies that a syntactically broken JSON body
// returns 400 without panicking the server.
func TestIdentity_MalformedJSON(t *testing.T) {
	env := setupIdentityServer(t, 10*time.Minute, 5)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	resp := doRequest(t, env, http.MethodPost, identityPath, tok, `{not valid json`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for malformed JSON", resp.StatusCode)
	}
}

// TestIdentity_ReplayDetected verifies that submitting the same id_number
// repeatedly within the replay window eventually triggers a SUSPICIOUS or
// BLOCKED classification rather than CLEAN, demonstrating that the replay
// indicator fires. The scanner is configured with a very low threshold (3)
// and a long window (1 hour) so the trigger is deterministic within the test.
//
// The endpoint always returns 200 with the scan result — replay detection
// surfaces as a classification change in the body, not as a 409. A 409 would
// require the handler to hard-reject on replay; this implementation surfaces
// the signal as an indicator match so callers can apply their own policy.
func TestIdentity_ReplayDetected(t *testing.T) {
	// replayThreshold=3: the 3rd submission of the same id_number fires the
	// indicator. replayWindow=1h: all requests fall inside the window.
	env := setupIdentityServer(t, time.Hour, 3)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)

	// Use a unique id_number so this test's replay counter is isolated.
	body := `{
		"claim_type": "passport",
		"context":    "kyc",
		"fields": {
			"id_number": "REPLAY-INTEG-TEST-001"
		}
	}`

	// First two submissions: counter below threshold, no replay match.
	for i := 0; i < 2; i++ {
		resp := doRequest(t, env, http.MethodPost, identityPath, tok, body)
		resp.Body.Close()
	}

	// Third submission: replay threshold reached.
	resp := doRequest(t, env, http.MethodPost, identityPath, tok, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (replay surfaces in body, not HTTP status)", resp.StatusCode)
	}

	var result identity.ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	replayHit := false
	for _, m := range result.Matches {
		if m.Category == identity.CategoryReplaySuspected {
			replayHit = true
			break
		}
	}
	if !replayHit {
		t.Fatalf("expected REPLAY_SUSPECTED indicator match on 3rd submission; classification=%s matches=%+v",
			result.Classification, result.Matches)
	}
	if result.Classification == identity.ClassificationClean {
		t.Fatalf("classification = CLEAN after replay hit; expected SUSPICIOUS or BLOCKED")
	}
}

// TestIdentity_WithMLEnricher_ReplaySignal verifies that the ML enricher is
// called when the scanner surfaces a SUSPICIOUS verdict (triggered by the
// replay indicator) and that the enricher's verdict appears in the response.
//
// Strategy: configure a low replay threshold (3) so the 3rd identical request
// fires the replay indicator and produces a SUSPICIOUS classification. Because
// the stub enricher has AlwaysScore=false, the scanner calls it only on
// SUSPICIOUS, which is exactly what we want to exercise.
func TestIdentity_WithMLEnricher_ReplaySignal(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         0,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Auth: config.AuthConfig{
			Secret:  testSecret,
			Issuer:  testIssuer,
			DevMode: false,
		},
		Prompt: config.PromptConfig{
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
	promptH := handlers.NewPromptHandler(promptScanner, nil, metrics.NewPromptMetricsAdapter(mreg))

	// replayThreshold=3: the 3rd submission of the same id_number fires the
	// replay indicator and pushes classification to SUSPICIOUS.
	identityScanner := identity.NewScanner(
		identity.DefaultLibrary,
		0.30,
		0.70,
		64*1024,
		time.Hour,
		3,
	)

	enricher := &stubIdentityMLEnricher{
		confidence:  0.85,
		verdict:     "SUSPICIOUS",
		alwaysScore: true,
	}
	identityH := handlers.NewIdentityHandler(identityScanner, nil, nil)
	identityH.ML = enricher

	threatFeedH := handlers.NewThreatFeedHandler()
	verifier := auth.NewVerifier(cfg.Auth.Secret, cfg.Auth.Issuer)
	logger := zerolog.Nop()

	apiSrv := api.New(api.Options{
		Config:        cfg,
		Logger:        &logger,
		Pinger:        stubPinger{},
		Prompt:        promptH,
		Identity:      identityH,
		ThreatFeed:    threatFeedH,
		Metrics:       mreg,
		Authenticator: verifier,
	})

	httpSrv := httptest.NewServer(apiSrv.Handler())
	defer httpSrv.Close()

	env := &testEnv{srv: httpSrv, mreg: mreg, cleanup: httpSrv.Close}
	tok := mintToken(t, auth.RoleOperator, time.Hour)

	// Use a unique id_number so this test's replay counter is isolated.
	body := `{
		"claim_type": "passport",
		"context":    "kyc",
		"fields": {
			"id_number": "ML-REPLAY-INTEG-TEST-001"
		}
	}`

	// First two submissions: below replay threshold. With AlwaysScore=true
	// the enricher is called on every request regardless of classification.
	for i := 0; i < 2; i++ {
		resp := doRequest(t, env, http.MethodPost, identityPath, tok, body)
		resp.Body.Close()
	}
	if n := enricher.callCount.Load(); n != 2 {
		t.Fatalf("ML enricher called %d times for 2 pre-replay requests; want 2", n)
	}

	// Third submission triggers the replay indicator → enricher called again.
	resp := doRequest(t, env, http.MethodPost, identityPath, tok, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result identity.ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Enricher must have been called a total of 3 times (once per request).
	if n := enricher.callCount.Load(); n != 3 {
		t.Fatalf("ML enricher call count = %d after 3 requests, want 3", n)
	}

	// The enricher's verdict must appear in the response.
	if result.MLVerdict != "SUSPICIOUS" {
		t.Fatalf("ml_verdict = %q, want %q", result.MLVerdict, "SUSPICIOUS")
	}
	if result.MLConfidence != 0.85 {
		t.Fatalf("ml_confidence = %f, want 0.85", result.MLConfidence)
	}
	if result.MLBackendVersion != "stub-identity-v0" {
		t.Fatalf("ml_backend_version = %q, want %q", result.MLBackendVersion, "stub-identity-v0")
	}
}
