package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/vertguard/internal/auth"
)

func TestThreatFeed_ListIOCs(t *testing.T) {
	env := setupServer(t, false)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleViewer, time.Hour)
	resp := doRequest(t, env, http.MethodGet, "/api/v1/threatfeed/iocs", tok, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	var arr any
	_ = json.NewDecoder(resp.Body).Decode(&arr)
	if arr == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestThreatFeed_MapATLAS(t *testing.T) {
	env := setupServer(t, false)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	body := `{"observed_behaviour":"Adversary attempts prompt injection to override system prompt"}`
	resp := doRequest(t, env, http.MethodPost, "/api/v1/threatfeed/atlas", tok, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(respBody))
	}
	out, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(out), "AML.T") {
		t.Fatalf("expected an AML.* technique in response: %s", string(out))
	}
}

func TestThreatFeed_Coverage(t *testing.T) {
	env := setupServer(t, false)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleViewer, time.Hour)
	resp := doRequest(t, env, http.MethodGet, "/api/v1/threatfeed/atlas/coverage", tok, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
}
