//go:build integration

// Package integration tests the OpenScrub HTTP API contract end-to-end
// against a running stack. Run with: go test -tags=integration ./tests/integration/...
//
// Requires:
//
//	OPENSCRUB_API_BASE     — default http://localhost:8087
//	OPENSCRUB_JWT_SECRET   — must match the secret the server is running with
//	OPENSCRUB_JWT_ISSUER   — default "openscrub"
//
// There is no /api/v1/auth/login endpoint — operator JWTs are minted by
// the operator's IDP (or by hand for local dev) and supplied via env.
// The test mints its own short-lived HS256 token.
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func base() string {
	if v := os.Getenv("OPENSCRUB_API_BASE"); v != "" {
		return v
	}
	return "http://localhost:8087"
}

// mintJWT builds an HS256 token signed with OPENSCRUB_JWT_SECRET.
// Skips the test (rather than failing) when the secret isn't set so
// `go test -tags=integration` is still useful in dev.
func mintJWT(t *testing.T, role string) string {
	t.Helper()
	secret := os.Getenv("OPENSCRUB_JWT_SECRET")
	if secret == "" {
		t.Skip("OPENSCRUB_JWT_SECRET unset — integration tests need a server-matching secret")
	}
	issuer := envOr("OPENSCRUB_JWT_ISSUER", "openscrub")
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  "integration-test",
		"role": role,
		"iss":  issuer,
		"exp":  time.Now().Add(5 * time.Minute).Unix(),
	})
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}
	return s
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func TestHealth(t *testing.T) {
	res, err := http.Get(base() + "/api/v1/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health: status %d", res.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["status"] != "ok" && out["status"] != "degraded" {
		t.Fatalf("unexpected status: %v", out["status"])
	}
}

func TestRulesLifecycle(t *testing.T) {
	tok := mintJWT(t, "operator")
	cli := &http.Client{Timeout: 10 * time.Second}

	body, _ := json.Marshal(map[string]any{
		"cidr":        "203.0.113.42/32",
		"type":        "blocklist",
		"ttl_seconds": 60,
	})
	req, _ := http.NewRequest(http.MethodPost, base()+"/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(res.Body)
		res.Body.Close()
		t.Fatalf("create: status %d: %s", res.StatusCode, raw)
	}
	var rule struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(res.Body).Decode(&rule)
	res.Body.Close()
	if rule.ID == "" {
		t.Fatal("missing rule id")
	}

	req, _ = http.NewRequest(http.MethodGet, base()+"/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err = cli.Do(req)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list: status %d", res.StatusCode)
	}
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/rules/%s", base(), rule.ID), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err = cli.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status %d", res.StatusCode)
	}
	res.Body.Close()
}

// /0 must be rejected — accidentally blocking the entire internet is a
// catastrophic operator error (drops all traffic, including the path
// the operator is using to remove the rule).
func TestRejectsDangerousCidr(t *testing.T) {
	tok := mintJWT(t, "operator")
	cli := &http.Client{Timeout: 10 * time.Second}
	body, _ := json.Marshal(map[string]any{
		"cidr":        "0.0.0.0/0",
		"type":        "blocklist",
		"ttl_seconds": 60,
	})
	req, _ := http.NewRequest(http.MethodPost, base()+"/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("create dangerous: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for /0 CIDR, got %d", res.StatusCode)
	}
}

func TestMitigationsListEmpty(t *testing.T) {
	tok := mintJWT(t, "auditor")
	req, _ := http.NewRequest(http.MethodGet, base()+"/api/v1/mitigations?limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("mitigations: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	var out struct {
		Mitigations []map[string]any `json:"mitigations"`
		Count       int              `json:"count"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out.Count < 0 {
		t.Fatal("negative count")
	}
}
