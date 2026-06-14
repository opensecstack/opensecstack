//go:build integration

// Package integration tests the OpenCSIRT HTTP API contract end-to-end
// against a running stack. Run with:
//
//	go test -tags=integration ./tests/integration/...
package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func base() string {
	if v := os.Getenv("OPENCSIRT_API_BASE"); v != "" {
		return v
	}
	return "http://localhost:8088"
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func login(t *testing.T) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": envOr("OPENCSIRT_TEST_USER", "operator"),
		"password": envOr("OPENCSIRT_TEST_PASS", "operator"),
	})
	res, err := http.Post(base()+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("login: status %d: %s", res.StatusCode, raw)
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
		Role      string `json:"role"`
		Sub       string `json:"sub"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if out.Token == "" {
		t.Fatal("empty token")
	}
	if out.Sub == "" {
		t.Fatal("expected sub in login response")
	}
	return out.Token
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
	for _, k := range []string{"status", "db", "advisory_service", "uptime_seconds"} {
		if _, ok := out[k]; !ok {
			t.Fatalf("health missing field %q: %v", k, out)
		}
	}
}

func TestConstituencyLifecycle(t *testing.T) {
	tok := login(t)
	cli := &http.Client{Timeout: 10 * time.Second}
	body, _ := json.Marshal(map[string]any{
		"name":   "ContractTest",
		"kind":   "important",
		"sector": "transport",
	})
	req, _ := http.NewRequest(http.MethodPost, base()+"/api/v1/constituencies", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("create: status %d: %s", res.StatusCode, raw)
	}
}

func TestRejectsInvalidKind(t *testing.T) {
	tok := login(t)
	cli := &http.Client{Timeout: 10 * time.Second}
	body, _ := json.Marshal(map[string]any{
		"name":   "BadKind",
		"kind":   "invalid_kind",
		"sector": "test",
	})
	req, _ := http.NewRequest(http.MethodPost, base()+"/api/v1/constituencies", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("create invalid: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest && res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 400/422 for invalid kind, got %d", res.StatusCode)
	}
}

func TestAdvisoryWithdraw(t *testing.T) {
	tok := login(t)
	cli := &http.Client{Timeout: 10 * time.Second}

	// 1. Create a draft advisory.
	body, _ := json.Marshal(map[string]any{
		"title": "ContractTest Advisory Withdraw",
		"tlp":   "green",
	})
	req, _ := http.NewRequest(http.MethodPost, base()+"/api/v1/advisories", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("create advisory: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("create advisory: status %d: %s", res.StatusCode, raw)
	}
	var advisory struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	if err := json.NewDecoder(res.Body).Decode(&advisory); err != nil {
		t.Fatalf("decode advisory: %v", err)
	}
	if advisory.ID == "" {
		t.Fatal("expected advisory id")
	}

	// 2. Publish the advisory.
	req, _ = http.NewRequest(http.MethodPost, base()+"/api/v1/advisories/"+advisory.ID+"/publish", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err = cli.Do(req)
	if err != nil {
		t.Fatalf("publish advisory: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("publish advisory: status %d: %s", res.StatusCode, raw)
	}

	// 3. Withdraw the published advisory — expect 200, state == "withdrawn".
	req, _ = http.NewRequest(http.MethodPost, base()+"/api/v1/advisories/"+advisory.ID+"/withdraw", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err = cli.Do(req)
	if err != nil {
		t.Fatalf("withdraw advisory: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("withdraw advisory: status %d: %s", res.StatusCode, raw)
	}
	var withdrawn struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(res.Body).Decode(&withdrawn); err != nil {
		t.Fatalf("decode withdraw response: %v", err)
	}
	if withdrawn.State != "withdrawn" {
		t.Fatalf("expected state withdrawn, got %q", withdrawn.State)
	}

	// 4. Attempt to withdraw again — expect 409.
	req, _ = http.NewRequest(http.MethodPost, base()+"/api/v1/advisories/"+advisory.ID+"/withdraw", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err = cli.Do(req)
	if err != nil {
		t.Fatalf("second withdraw: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("expected 409 on second withdraw, got %d: %s", res.StatusCode, raw)
	}
}

func TestIncidentEscalate(t *testing.T) {
	tok := login(t)
	cli := &http.Client{Timeout: 10 * time.Second}

	// 1. Create an incident.
	body, _ := json.Marshal(map[string]any{
		"title":    "ContractTest Incident Escalate",
		"severity": "medium",
	})
	req, _ := http.NewRequest(http.MethodPost, base()+"/api/v1/incidents", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("create incident: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("create incident: status %d: %s", res.StatusCode, raw)
	}
	var incident struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(res.Body).Decode(&incident); err != nil {
		t.Fatalf("decode incident: %v", err)
	}
	if incident.ID == "" {
		t.Fatal("expected incident id")
	}

	// 2. Escalate the incident — expect 200, status == "triaged".
	req, _ = http.NewRequest(http.MethodPost, base()+"/api/v1/incidents/"+incident.ID+"/escalate", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err = cli.Do(req)
	if err != nil {
		t.Fatalf("escalate incident: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("escalate incident: status %d: %s", res.StatusCode, raw)
	}
	var escalated struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(res.Body).Decode(&escalated); err != nil {
		t.Fatalf("decode escalate response: %v", err)
	}
	if escalated.Status != "triaged" {
		t.Fatalf("expected status triaged, got %q", escalated.Status)
	}
}

// loginAs is a variant of login that accepts explicit credentials instead of
// reading from environment variables.  Used by 403 sub-tests that need a lower-
// privileged account.  If the server returns a non-200 status the test is
// skipped (not failed) so that environments that only configure a single user
// are not broken by these assertions.
func loginAs(t *testing.T, username, password string) (string, bool) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	res, err := http.Post(base()+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("loginAs %s: %v", username, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", false // caller should t.Skip
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("loginAs %s decode: %v", username, err)
	}
	return out.Token, out.Token != ""
}

// TestAdvisoryWithdrawForbidden checks that a user whose role is below
// csirt_lead (rank 5) receives 403 when attempting to withdraw an advisory.
// The test uses the OPENCSIRT_TEST_ANALYST_USER / OPENCSIRT_TEST_ANALYST_PASS
// environment variables (defaulting to "analyst"/"analyst") to obtain a
// lower-privileged token.  If those credentials are not configured in the
// running stack the test is skipped automatically.
func TestAdvisoryWithdrawForbidden(t *testing.T) {
	// Obtain a csirt_lead token to create and publish the advisory.
	operTok := login(t)
	cli := &http.Client{Timeout: 10 * time.Second}

	// 1. Create a draft advisory with the privileged account.
	body, _ := json.Marshal(map[string]any{
		"title": "ContractTest Advisory Withdraw Forbidden",
		"tlp":   "green",
	})
	req, _ := http.NewRequest(http.MethodPost, base()+"/api/v1/advisories", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+operTok)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("create advisory: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("create advisory: status %d: %s", res.StatusCode, raw)
	}
	var adv struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&adv); err != nil {
		t.Fatalf("decode advisory: %v", err)
	}
	if adv.ID == "" {
		t.Fatal("expected advisory id")
	}

	// 2. Publish the advisory so it is in a withdrawable state.
	req, _ = http.NewRequest(http.MethodPost, base()+"/api/v1/advisories/"+adv.ID+"/publish", nil)
	req.Header.Set("Authorization", "Bearer "+operTok)
	res, err = cli.Do(req)
	if err != nil {
		t.Fatalf("publish advisory: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("publish advisory: status %d: %s", res.StatusCode, raw)
	}

	// 3. Obtain an analyst-level token (rank < csirt_lead).  Skip if the
	//    account is not available in this environment.
	analystUser := envOr("OPENCSIRT_TEST_ANALYST_USER", "analyst")
	analystPass := envOr("OPENCSIRT_TEST_ANALYST_PASS", "analyst")
	analystTok, ok := loginAs(t, analystUser, analystPass)
	if !ok {
		t.Skipf("analyst account %q not configured — skipping 403 check", analystUser)
	}

	// 4. Attempt to withdraw with the analyst token — expect 403.
	req, _ = http.NewRequest(http.MethodPost, base()+"/api/v1/advisories/"+adv.ID+"/withdraw", nil)
	req.Header.Set("Authorization", "Bearer "+analystTok)
	res, err = cli.Do(req)
	if err != nil {
		t.Fatalf("withdraw (analyst): %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("expected 403 for analyst withdraw, got %d: %s", res.StatusCode, raw)
	}
}

// TestIncidentEscalateNotFound checks that escalating a non-existent incident
// returns 404.
func TestIncidentEscalateNotFound(t *testing.T) {
	tok := login(t)
	cli := &http.Client{Timeout: 10 * time.Second}

	// Use a well-formed but guaranteed-absent UUID.
	nonExistentID := "00000000-0000-0000-0000-000000000001"
	req, _ := http.NewRequest(http.MethodPost, base()+"/api/v1/incidents/"+nonExistentID+"/escalate", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("escalate non-existent: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("expected 404 for non-existent incident escalate, got %d: %s", res.StatusCode, raw)
	}
}

// TestIncidentEscalateForbidden checks that a user whose role is below
// operator (rank 4) receives 403 when attempting to escalate an incident.
// Uses OPENCSIRT_TEST_ANALYST_USER / OPENCSIRT_TEST_ANALYST_PASS (defaulting
// to "analyst"/"analyst").  Skipped automatically when those credentials are
// not present in the running stack.
func TestIncidentEscalateForbidden(t *testing.T) {
	// Obtain an operator token to create the incident.
	operTok := login(t)
	cli := &http.Client{Timeout: 10 * time.Second}

	// 1. Create an incident with the operator account.
	body, _ := json.Marshal(map[string]any{
		"title":    "ContractTest Incident Escalate Forbidden",
		"severity": "low",
	})
	req, _ := http.NewRequest(http.MethodPost, base()+"/api/v1/incidents", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+operTok)
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("create incident: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("create incident: status %d: %s", res.StatusCode, raw)
	}
	var inc struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&inc); err != nil {
		t.Fatalf("decode incident: %v", err)
	}
	if inc.ID == "" {
		t.Fatal("expected incident id")
	}

	// 2. Obtain an analyst-level token (rank < operator).  Skip if the
	//    account is not available in this environment.
	analystUser := envOr("OPENCSIRT_TEST_ANALYST_USER", "analyst")
	analystPass := envOr("OPENCSIRT_TEST_ANALYST_PASS", "analyst")
	analystTok, ok := loginAs(t, analystUser, analystPass)
	if !ok {
		t.Skipf("analyst account %q not configured — skipping 403 check", analystUser)
	}

	// 3. Attempt to escalate with the analyst token — expect 403.
	req, _ = http.NewRequest(http.MethodPost, base()+"/api/v1/incidents/"+inc.ID+"/escalate", nil)
	req.Header.Set("Authorization", "Bearer "+analystTok)
	res, err = cli.Do(req)
	if err != nil {
		t.Fatalf("escalate (analyst): %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("expected 403 for analyst escalate, got %d: %s", res.StatusCode, raw)
	}
}
