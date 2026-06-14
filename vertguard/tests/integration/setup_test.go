// Package integration exercises VertGuard's full HTTP stack
// (chi router + middleware + auth + handlers) without external
// dependencies. Postgres-backed paths are skipped unless
// VERTGUARD_TEST_DB_URL is set; metrics + scan + threatfeed paths
// run everywhere.
package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/api"
	"github.com/opensecstack/vertguard/internal/api/handlers"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/metrics"
	"github.com/opensecstack/vertguard/internal/prompt"
)

const (
	testIssuer = "vertguard-test"
	testSecret = "integration-test-secret-key-32bytes-min"
)

type stubPinger struct{ err error }

func (s stubPinger) Ping(context.Context) error { return s.err }

type testEnv struct {
	srv     *httptest.Server
	mreg    *metrics.Registry
	cleanup func()
}

func setupServer(t *testing.T, devMode bool) *testEnv {
	return setupServerWithPinger(t, devMode, stubPinger{})
}

// setupServerWithPinger lets readyz tests inject a failing pinger.
func setupServerWithPinger(t *testing.T, devMode bool, pinger handlers.Pinger) *testEnv {
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
	}

	mreg := metrics.New()
	scanner := prompt.NewScanner(
		prompt.DefaultLibrary,
		cfg.Prompt.CleanThreshold,
		cfg.Prompt.BlockThreshold,
		int(cfg.Prompt.MaxInputSize),
	)
	promptH := handlers.NewPromptHandler(
		scanner, nil, metrics.NewPromptMetricsAdapter(mreg),
	)
	threatFeedH := handlers.NewThreatFeedHandler()
	verifier := auth.NewVerifier(cfg.Auth.Secret, cfg.Auth.Issuer)
	logger := zerolog.Nop()

	apiSrv := api.New(api.Options{
		Config:        cfg,
		Logger:        &logger,
		Pinger:        pinger,
		Prompt:        promptH,
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

// mintToken hand-rolls an HS256 JWT matching the test secret + issuer.
func mintToken(t *testing.T, role string, ttl time.Duration) string {
	return mintTokenWithSecret(t, testSecret, role, ttl)
}

// mintTokenWithSecret hand-rolls an HS256 JWT signed with an arbitrary
// secret. Used by rotation tests that need to exercise the verifier's
// secondary slots.
func mintTokenWithSecret(t *testing.T, secret, role string, ttl time.Duration) string {
	t.Helper()
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{
		"sub":  "test-user",
		"role": role,
		"iss":  testIssuer,
		"exp":  time.Now().Add(ttl).Unix(),
		"iat":  time.Now().Unix(),
	}
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signedInput := enc(header) + "." + enc(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedInput))
	return signedInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// setupServerMultiSecret builds a test environment with primary + next
// secrets active, modelling a mid-rotation deployment.
func setupServerMultiSecret(t *testing.T, primary, next string) *testEnv {
	t.Helper()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         0,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Auth: config.AuthConfig{
			Secret:     primary,
			SecretNext: next,
			Issuer:     testIssuer,
		},
		Prompt: config.PromptConfig{
			CleanThreshold: 0.30,
			BlockThreshold: 0.70,
			MaxInputSize:   1024 * 1024,
		},
	}

	mreg := metrics.New()
	scanner := prompt.NewScanner(
		prompt.DefaultLibrary,
		cfg.Prompt.CleanThreshold,
		cfg.Prompt.BlockThreshold,
		int(cfg.Prompt.MaxInputSize),
	)
	promptH := handlers.NewPromptHandler(
		scanner, nil, metrics.NewPromptMetricsAdapter(mreg),
	)
	threatFeedH := handlers.NewThreatFeedHandler()
	verifier := auth.NewVerifierMulti(cfg.Auth.ActiveSecrets(), cfg.Auth.Issuer)
	verifier.SetMetrics(metrics.NewAuthMetricsAdapter(mreg))
	logger := zerolog.Nop()

	apiSrv := api.New(api.Options{
		Config:        cfg,
		Logger:        &logger,
		Pinger:        stubPinger{},
		Prompt:        promptH,
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

func doRequest(t *testing.T, env *testEnv, method, path, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, env.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}
