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
	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/auth/denylist"
	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/metrics"
	"github.com/opensecstack/vertguard/internal/prompt"
)

type denylistEnv struct {
	srv   *httptest.Server
	store denylist.Store
	cache *denylist.Cache
}

func setupDenylistServer(t *testing.T) *denylistEnv {
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
	scanner := prompt.NewScanner(
		prompt.DefaultLibrary,
		cfg.Prompt.CleanThreshold,
		cfg.Prompt.BlockThreshold,
		int(cfg.Prompt.MaxInputSize),
	)
	promptH := handlers.NewPromptHandler(
		scanner, nil, metrics.NewPromptMetricsAdapter(mreg),
	)
	verifier := auth.NewVerifier(cfg.Auth.Secret, cfg.Auth.Issuer)
	logger := zerolog.Nop()

	store := denylist.NewMemoryStore()
	cache := denylist.NewCache(store, denylist.WithLogger(&logger))
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	auditSink := audit.NewMultiSink(&logger, audit.NewLoggerSink(&logger))
	denyAdmin := handlers.NewDenylistAdminHandler(store, cache, auditSink, &logger)

	apiSrv := api.New(api.Options{
		Config:        cfg,
		Logger:        &logger,
		Pinger:        stubPinger{},
		Prompt:        promptH,
		Metrics:       mreg,
		Authenticator: verifier,
		TokenRevoker:  cache,
		Denylist:      denyAdmin,
		AuditSink:     auditSink,
	})

	httpSrv := httptest.NewServer(apiSrv.Handler())
	t.Cleanup(httpSrv.Close)
	return &denylistEnv{srv: httpSrv, store: store, cache: cache}
}

// mintTokenWithJTI mirrors mintToken but lets the caller pin a jti.
func mintTokenWithJTI(t *testing.T, role, jti string, ttl time.Duration) string {
	t.Helper()
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{
		"sub":  "alice",
		"role": role,
		"iss":  testIssuer,
		"exp":  time.Now().Add(ttl).Unix(),
		"iat":  time.Now().Unix(),
		"jti":  jti,
	}
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signed := enc(header) + "." + enc(claims)
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func doDenyRequest(t *testing.T, srv *httptest.Server, method, path, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
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

func TestDenylist_RevokeJTIBlocksScan(t *testing.T) {
	env := setupDenylistServer(t)

	tok := mintTokenWithJTI(t, auth.RoleOperator, "tok-1", time.Hour)

	// 1) Scan succeeds before revocation.
	resp := doDenyRequest(t, env.srv, http.MethodPost, "/api/v1/prompt/scan", tok, `{"input":"hello"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke status=%d want 200", resp.StatusCode)
	}

	// 2) Admin revokes via the API.
	adminTok := mintToken(t, auth.RoleAdmin, time.Hour)
	body := `{"kind":"jti","value":"tok-1","reason":"compromised"}`
	resp = doDenyRequest(t, env.srv, http.MethodPost, "/api/v1/admin/denylist", adminTok, body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("revoke status=%d want 201", resp.StatusCode)
	}

	// 3) Scan now blocked.
	resp = doDenyRequest(t, env.srv, http.MethodPost, "/api/v1/prompt/scan", tok, `{"input":"hello"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-revoke status=%d want 401", resp.StatusCode)
	}
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), `"code":"token_revoked"`) {
		t.Fatalf("expected token_revoked code, body=%q", string(buf[:n]))
	}
}

func TestDenylist_UnrevokeRestoresAccess(t *testing.T) {
	env := setupDenylistServer(t)
	tok := mintTokenWithJTI(t, auth.RoleOperator, "tok-2", time.Hour)
	adminTok := mintToken(t, auth.RoleAdmin, time.Hour)

	// Revoke
	doDenyRequest(t, env.srv, http.MethodPost, "/api/v1/admin/denylist", adminTok,
		`{"kind":"jti","value":"tok-2"}`).Body.Close()
	resp := doDenyRequest(t, env.srv, http.MethodPost, "/api/v1/prompt/scan", tok, `{"input":"hi"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after revoke, got %d", resp.StatusCode)
	}

	// Un-revoke
	resp = doDenyRequest(t, env.srv, http.MethodDelete, "/api/v1/admin/denylist/jti/tok-2", adminTok, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d want 204", resp.StatusCode)
	}

	resp = doDenyRequest(t, env.srv, http.MethodPost, "/api/v1/prompt/scan", tok, `{"input":"hi"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post-unrevoke status=%d want 200", resp.StatusCode)
	}
}

func TestDenylist_ListReturnsEntries(t *testing.T) {
	env := setupDenylistServer(t)
	adminTok := mintToken(t, auth.RoleAdmin, time.Hour)

	doDenyRequest(t, env.srv, http.MethodPost, "/api/v1/admin/denylist", adminTok,
		`{"kind":"sub","value":"bob","reason":"off-boarded"}`).Body.Close()

	resp := doDenyRequest(t, env.srv, http.MethodGet, "/api/v1/admin/denylist", adminTok, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status=%d", resp.StatusCode)
	}
	var got struct {
		Entries []denylist.Entry `json:"entries"`
		Count   int              `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Count != 1 || got.Entries[0].Value != "bob" {
		t.Fatalf("unexpected list payload: %+v", got)
	}
}

func TestDenylist_NonAdminBlocked(t *testing.T) {
	env := setupDenylistServer(t)
	opTok := mintToken(t, auth.RoleOperator, time.Hour)
	resp := doDenyRequest(t, env.srv, http.MethodPost, "/api/v1/admin/denylist", opTok,
		`{"kind":"jti","value":"x"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin status=%d want 403", resp.StatusCode)
	}
}
