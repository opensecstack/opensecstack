package citadel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// capturedRequest holds details of a single HTTP request received by a test server.
type capturedRequest struct {
	method  string
	path    string
	headers http.Header
	body    map[string]interface{}
}

// newCaptureServer returns an httptest.Server that forwards every received request
// to the returned channel (buffered to avoid blocking the handler goroutine).
func newCaptureServer(t *testing.T, statusCode int, responseBody string, ch chan<- capturedRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		ch <- capturedRequest{
			method:  r.Method,
			path:    r.URL.Path,
			headers: r.Header.Clone(),
			body:    body,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if responseBody != "" {
			_, _ = w.Write([]byte(responseBody))
		}
	}))
}

// drain calls c.Drain with a generous timeout to prevent test hangs.
func drain(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.Drain(ctx)
}

// ---------------------------------------------------------------------------
// No-op / disabled client
// ---------------------------------------------------------------------------

func TestClient_NoOp_WhenBaseURLEmpty(t *testing.T) {
	ch := make(chan capturedRequest, 1)
	ts := newCaptureServer(t, http.StatusOK, `{}`, ch)
	defer ts.Close()

	c := New("", "key-1", "secret")
	c.LogEvent("scan.started", "u1", "operator", "EXECUTED", "apiguard", "res-1", nil)

	drain(t, c)
	select {
	case req := <-ch:
		t.Errorf("expected no HTTP request, but received one: %+v", req)
	default:
		// correct — nothing was sent
	}
}

func TestClient_EvaluateScan_DisabledNoOp(t *testing.T) {
	c := New("", "key-1", "secret")
	k := &Kerkese{KerkeseVersion: "1.0", TsUTC: time.Now(), ProjectID: "p1", ExecutionID: uuid.New()}
	decision, err := c.EvaluateScan(context.Background(), k)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if decision != nil {
		t.Fatalf("expected nil decision, got %+v", decision)
	}
}

func TestClient_EmitWORM_Disabled(t *testing.T) {
	c := New("", "key-1", "secret")
	entryID, chainHash, err := c.EmitWORM(context.Background(), "apiguard", "scan.started", "proj1", nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if entryID != "" || chainHash != "" {
		t.Errorf("expected empty strings, got entryID=%q chainHash=%q", entryID, chainHash)
	}
}

// ---------------------------------------------------------------------------
// HMAC authentication headers
// ---------------------------------------------------------------------------

func TestClient_HMAC_Headers_Present(t *testing.T) {
	ch := make(chan capturedRequest, 1)
	wormResp := `{"worm_entry_id":"` + uuid.New().String() + `","chain_hash":"abc123"}`
	ts := newCaptureServer(t, http.StatusOK, wormResp, ch)
	defer ts.Close()

	c := New(ts.URL, "my-key-id", "my-secret")
	_, _, err := c.EmitWORM(context.Background(), "apiguard", "test.event", "proj1", nil)
	if err != nil {
		t.Fatalf("EmitWORM failed: %v", err)
	}

	select {
	case req := <-ch:
		if req.headers.Get("X-CITADEL-KEY") != "my-key-id" {
			t.Errorf("X-CITADEL-KEY = %q, want %q", req.headers.Get("X-CITADEL-KEY"), "my-key-id")
		}
		if req.headers.Get("X-CITADEL-TS") == "" {
			t.Error("X-CITADEL-TS header is missing")
		}
		sig := req.headers.Get("X-CITADEL-SIG")
		if !strings.HasPrefix(sig, "hmac-sha256=") {
			t.Errorf("X-CITADEL-SIG = %q, want prefix 'hmac-sha256='", sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for request")
	}
}

func TestClient_HMAC_NoAuthorizationBearerHeader(t *testing.T) {
	ch := make(chan capturedRequest, 1)
	wormResp := `{"worm_entry_id":"` + uuid.New().String() + `","chain_hash":"abc"}`
	ts := newCaptureServer(t, http.StatusOK, wormResp, ch)
	defer ts.Close()

	c := New(ts.URL, "k", "s")
	_, _, _ = c.EmitWORM(context.Background(), "apiguard", "e", "p", nil)

	select {
	case req := <-ch:
		if req.headers.Get("Authorization") != "" {
			t.Errorf("unexpected Authorization header: %q", req.headers.Get("Authorization"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

// ---------------------------------------------------------------------------
// EmitWORM
// ---------------------------------------------------------------------------

func TestClient_EmitWORM_Success(t *testing.T) {
	wantEntryID := uuid.New().String()
	wantChainHash := "deadbeef01234567"
	wormResp := `{"worm_entry_id":"` + wantEntryID + `","chain_hash":"` + wantChainHash + `"}`

	ch := make(chan capturedRequest, 1)
	ts := newCaptureServer(t, http.StatusOK, wormResp, ch)
	defer ts.Close()

	c := New(ts.URL, "k", "s")
	entryID, chainHash, err := c.EmitWORM(context.Background(), "apiguard", "scan.completed", "proj-42", map[string]any{
		"total_findings": 3,
	})
	if err != nil {
		t.Fatalf("EmitWORM error: %v", err)
	}
	if entryID != wantEntryID {
		t.Errorf("entryID = %q, want %q", entryID, wantEntryID)
	}
	if chainHash != wantChainHash {
		t.Errorf("chainHash = %q, want %q", chainHash, wantChainHash)
	}

	select {
	case req := <-ch:
		if req.path != "/api/v1/worm/emit" {
			t.Errorf("path = %q, want /api/v1/worm/emit", req.path)
		}
		if req.method != http.MethodPost {
			t.Errorf("method = %q, want POST", req.method)
		}
		if req.body["source"] != "apiguard" {
			t.Errorf("source = %v, want apiguard", req.body["source"])
		}
		if req.body["event_type"] != "scan.completed" {
			t.Errorf("event_type = %v, want scan.completed", req.body["event_type"])
		}
		if req.body["project_id"] != "proj-42" {
			t.Errorf("project_id = %v, want proj-42", req.body["project_id"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for request")
	}
}

func TestClient_EmitWORM_ServerError_ReturnsError(t *testing.T) {
	ch := make(chan capturedRequest, 1)
	ts := newCaptureServer(t, http.StatusInternalServerError, `{}`, ch)
	defer ts.Close()

	c := New(ts.URL, "k", "s")
	_, _, err := c.EmitWORM(context.Background(), "apiguard", "ev", "p", nil)
	if err == nil {
		t.Error("expected error on 500, got nil")
	}
}

// ---------------------------------------------------------------------------
// EvaluateScan
// ---------------------------------------------------------------------------

func TestClient_EvaluateScan_ExecuteOutcome(t *testing.T) {
	execID := uuid.New()
	decisionResp, _ := json.Marshal(Decision{
		Outcome:     OutcomeExecute,
		ExecutionID: execID,
		Reasons:     []string{},
	})

	ch := make(chan capturedRequest, 1)
	ts := newCaptureServer(t, http.StatusOK, string(decisionResp), ch)
	defer ts.Close()

	c := New(ts.URL, "k", "s")
	k := &Kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Now().UTC(),
		ProjectID:      "proj-1",
		ExecutionID:    execID,
		Action:         KerkeseAction{Type: "deploy_change", ChangeID: "scan-001"},
		Actor:          KerkeseActor{UserID: 0, Role: "group_sig_operator"},
		Verifier:       KerkeseVerifier{UserID: 0, Role: "group_sig_verifier"},
		SoD:            KerkeseSoD{},
	}

	decision, err := c.EvaluateScan(context.Background(), k)
	if err != nil {
		t.Fatalf("EvaluateScan error: %v", err)
	}
	if decision == nil {
		t.Fatal("expected non-nil decision")
	}
	if decision.Outcome != OutcomeExecute {
		t.Errorf("outcome = %q, want %q", decision.Outcome, OutcomeExecute)
	}

	select {
	case req := <-ch:
		if req.path != "/api/v1/marshal/evaluate" {
			t.Errorf("path = %q, want /api/v1/marshal/evaluate", req.path)
		}
		if req.method != http.MethodPost {
			t.Errorf("method = %q, want POST", req.method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

func TestClient_EvaluateScan_RefuseOutcome(t *testing.T) {
	decisionResp, _ := json.Marshal(Decision{
		Outcome:     OutcomeRefuse,
		ExecutionID: uuid.New(),
		Reasons:     []string{"gate 3 failed: project is frozen"},
	})

	ch := make(chan capturedRequest, 1)
	ts := newCaptureServer(t, http.StatusOK, string(decisionResp), ch)
	defer ts.Close()

	c := New(ts.URL, "k", "s")
	k := &Kerkese{KerkeseVersion: "1.0", TsUTC: time.Now(), ProjectID: "p", ExecutionID: uuid.New()}

	decision, err := c.EvaluateScan(context.Background(), k)
	if err != nil {
		t.Fatalf("EvaluateScan error: %v", err)
	}
	if decision.Outcome != OutcomeRefuse {
		t.Errorf("outcome = %q, want REFUSE", decision.Outcome)
	}
	if len(decision.Reasons) == 0 {
		t.Error("expected non-empty reasons on REFUSE")
	}
	<-ch // consume
}

func TestClient_EvaluateScan_ServerError_ReturnsError(t *testing.T) {
	ch := make(chan capturedRequest, 1)
	ts := newCaptureServer(t, http.StatusInternalServerError, `{}`, ch)
	defer ts.Close()

	c := New(ts.URL, "k", "s")
	k := &Kerkese{KerkeseVersion: "1.0", TsUTC: time.Now(), ProjectID: "p", ExecutionID: uuid.New()}

	_, err := c.EvaluateScan(context.Background(), k)
	if err == nil {
		t.Error("expected error on 500, got nil")
	}
	<-ch // consume
}

// ---------------------------------------------------------------------------
// LogEvent (fire-and-forget → WORM emit)
// ---------------------------------------------------------------------------

func TestClient_LogEvent_RoutesToWORMEndpoint(t *testing.T) {
	wormResp := `{"worm_entry_id":"` + uuid.New().String() + `","chain_hash":"x"}`
	ch := make(chan capturedRequest, 1)
	ts := newCaptureServer(t, http.StatusOK, wormResp, ch)
	defer ts.Close()

	c := New(ts.URL, "k", "s")
	c.LogEvent("scan.started", "u1", "operator", "EXECUTED", "apiguard", "scan-1", nil)
	drain(t, c)

	select {
	case req := <-ch:
		if req.path != "/api/v1/worm/emit" {
			t.Errorf("LogEvent routed to %q, want /api/v1/worm/emit", req.path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for LogEvent request")
	}
}

func TestClient_LogEvent_ServerError500_SilentlyDiscarded(t *testing.T) {
	ch := make(chan capturedRequest, 1)
	ts := newCaptureServer(t, http.StatusInternalServerError, `{}`, ch)
	defer ts.Close()

	c := New(ts.URL, "k", "s")
	// LogEvent must not block or panic even when server returns 500.
	c.LogEvent("scan.failed", "", "", "error", "apiguard", "scan-2", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.Drain(ctx)

	select {
	case <-ch:
		// good — server received the request
	default:
		t.Error("expected server to receive the request even on 500 response")
	}
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

func TestClient_Drain_RespectsContextCancellation(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()

	c := New(slow.URL, "k", "s")
	c.LogEvent("e", "", "", "s", "m", "r", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	c.Drain(ctx)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Drain did not respect context cancellation; took %v", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Nil client safety
// ---------------------------------------------------------------------------

func TestClient_NilClient_IsSafe(t *testing.T) {
	var c *Client

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic on nil client: %v", r)
		}
	}()

	c.LogEvent("e", "", "", "s", "m", "r", nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c.Drain(ctx)

	// EvaluateScan and EmitWORM must also be nil-safe.
	_, err := c.EvaluateScan(ctx, &Kerkese{})
	if err != nil {
		t.Errorf("nil EvaluateScan returned error: %v", err)
	}
	_, _, err = c.EmitWORM(ctx, "s", "e", "p", nil)
	if err != nil {
		t.Errorf("nil EmitWORM returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestClient_MultipleConcurrentLogEvents(t *testing.T) {
	const n = 10
	wormResp := `{"worm_entry_id":"` + uuid.New().String() + `","chain_hash":"h"}`
	ch := make(chan capturedRequest, n)
	ts := newCaptureServer(t, http.StatusOK, wormResp, ch)
	defer ts.Close()

	c := New(ts.URL, "k", "s")

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.LogEvent("e", "", "", "s", "m", "r", nil)
		}()
	}
	wg.Wait()
	drain(t, c)

	received := 0
loop:
	for {
		select {
		case <-ch:
			received++
		default:
			break loop
		}
	}
	if received != n {
		t.Errorf("expected %d requests, received %d", n, received)
	}
}

// ---------------------------------------------------------------------------
// NIS2 mapping
// ---------------------------------------------------------------------------

func TestNIS2Measure_CommonOWASPIDs(t *testing.T) {
	cases := []struct{ owaspID, wantCode string }{
		{"API1:2023", "e"},
		{"API4:2023", "d"},
		{"API10:2023", "g"},
	}
	for _, tc := range cases {
		got, ok := NIS2Measure[tc.owaspID]
		if !ok {
			t.Errorf("NIS2Measure[%q] not found", tc.owaspID)
			continue
		}
		if got != tc.wantCode {
			t.Errorf("NIS2Measure[%q] = %q, want %q", tc.owaspID, got, tc.wantCode)
		}
	}
}

func TestNIS2Measure_AllTenOWASPIDsPresent(t *testing.T) {
	for i := 1; i <= 10; i++ {
		id := fmt.Sprintf("API%d:2023", i)
		if _, ok := NIS2Measure[id]; !ok {
			t.Errorf("NIS2Measure missing entry for %q", id)
		}
	}
}
