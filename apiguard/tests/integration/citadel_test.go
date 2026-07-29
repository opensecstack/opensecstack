//go:build integration

package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/opensecstack/apiguard/internal/citadel"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newMockCITADEL creates an httptest.Server that delegates to the given handler
// and returns both the server and a citadel.Client pointed at it. The caller
// must close the server when done (typically via t.Cleanup or defer).
func newMockCITADEL(t *testing.T, secret string, handler http.HandlerFunc) (*httptest.Server, *citadel.Client) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	client := citadel.New(ts.URL, "test-key", secret)
	return ts, client
}

// verifyHMAC recomputes the HMAC-SHA256 signature from the received headers and
// request body, returning true when the signature is valid for the given secret.
func verifyHMAC(r *http.Request, body []byte, secret string) bool {
	keyID := r.Header.Get("X-CITADEL-KEY")
	ts := r.Header.Get("X-CITADEL-TS")
	sig := r.Header.Get("X-CITADEL-SIG")

	if keyID == "" || ts == "" || sig == "" {
		return false
	}

	// Strip the "hmac-sha256=" prefix.
	const prefix = "hmac-sha256="
	if !strings.HasPrefix(sig, prefix) {
		return false
	}
	receivedHex := sig[len(prefix):]

	bodyHash := sha256.Sum256(body)
	message := keyID + ":" + ts + ":" + hex.EncodeToString(bodyHash[:])

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedHex := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(receivedHex), []byte(expectedHex))
}

// respondJSON writes a JSON response with the given status code.
func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// newKerkese builds a minimal valid Kerkese payload for testing.
func newKerkese() *citadel.Kerkese {
	return &citadel.Kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Now().UTC(),
		ProjectID:      "integration-test",
		ExecutionID:    uuid.New(),
		Action: citadel.KerkeseAction{
			Type:     "api_scan",
			ChangeID: "scan-integration-001",
		},
		Actor:    citadel.KerkeseActor{UserID: "1", Role: "operator"},
		Verifier: citadel.KerkeseVerifier{UserID: "2", Role: "verifier"},
	}
}

// ---------------------------------------------------------------------------
// 1. EvaluateScan — EXECUTE
// ---------------------------------------------------------------------------

func TestIntegration_EvaluateScan_EXECUTE(t *testing.T) {
	const secret = "test-secret-execute"
	execID := uuid.New()

	_, client := newMockCITADEL(t, secret, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		// Verify HMAC headers are present and valid.
		if !verifyHMAC(r, body, secret) {
			http.Error(w, "invalid HMAC", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/marshal/evaluate" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		respondJSON(w, http.StatusOK, citadel.Decision{
			Outcome:     citadel.OutcomeExecute,
			ExecutionID: execID,
			Reasons:     []string{},
			TsUTC:       time.Now().UTC(),
		})
	})

	decision, err := client.EvaluateScan(context.Background(), newKerkese())
	if err != nil {
		t.Fatalf("EvaluateScan returned error: %v", err)
	}
	if decision == nil {
		t.Fatal("expected non-nil decision")
	}
	if decision.Outcome != citadel.OutcomeExecute {
		t.Errorf("outcome = %q, want %q", decision.Outcome, citadel.OutcomeExecute)
	}
}

// ---------------------------------------------------------------------------
// 2. EvaluateScan — REFUSE
// ---------------------------------------------------------------------------

func TestIntegration_EvaluateScan_REFUSE(t *testing.T) {
	const secret = "test-secret-refuse"

	_, client := newMockCITADEL(t, secret, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !verifyHMAC(r, body, secret) {
			http.Error(w, "invalid HMAC", http.StatusUnauthorized)
			return
		}

		respondJSON(w, http.StatusOK, citadel.Decision{
			Outcome:     citadel.OutcomeRefuse,
			ExecutionID: uuid.New(),
			Reasons:     []string{"gate 2 failed: project frozen", "SoD violation detected"},
			Gates: []citadel.GateResult{
				{Gate: 1, Name: "approval", Status: "PASS"},
				{Gate: 2, Name: "freeze_window", Status: "FAIL", Reason: "project frozen"},
			},
			TsUTC: time.Now().UTC(),
		})
	})

	decision, err := client.EvaluateScan(context.Background(), newKerkese())
	if err != nil {
		t.Fatalf("EvaluateScan returned error: %v", err)
	}
	if decision == nil {
		t.Fatal("expected non-nil decision")
	}
	if decision.Outcome != citadel.OutcomeRefuse {
		t.Errorf("outcome = %q, want %q", decision.Outcome, citadel.OutcomeRefuse)
	}
	if len(decision.Reasons) == 0 {
		t.Error("expected non-empty reasons for REFUSE outcome")
	}
	if len(decision.Reasons) != 2 {
		t.Errorf("expected 2 reasons, got %d", len(decision.Reasons))
	}
}

// ---------------------------------------------------------------------------
// 3. EvaluateScan — HARD_STOP
// ---------------------------------------------------------------------------

func TestIntegration_EvaluateScan_HARD_STOP(t *testing.T) {
	const secret = "test-secret-hardstop"

	_, client := newMockCITADEL(t, secret, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !verifyHMAC(r, body, secret) {
			http.Error(w, "invalid HMAC", http.StatusUnauthorized)
			return
		}

		respondJSON(w, http.StatusOK, citadel.Decision{
			Outcome:     citadel.OutcomeHardStop,
			ExecutionID: uuid.New(),
			Reasons:     []string{"critical policy violation: emergency override required"},
			TsUTC:       time.Now().UTC(),
		})
	})

	decision, err := client.EvaluateScan(context.Background(), newKerkese())
	if err != nil {
		t.Fatalf("EvaluateScan returned error: %v", err)
	}
	if decision == nil {
		t.Fatal("expected non-nil decision")
	}
	if decision.Outcome != citadel.OutcomeHardStop {
		t.Errorf("outcome = %q, want %q", decision.Outcome, citadel.OutcomeHardStop)
	}
}

// ---------------------------------------------------------------------------
// 4. EmitWORM — Success
// ---------------------------------------------------------------------------

func TestIntegration_EmitWORM_Success(t *testing.T) {
	const secret = "test-secret-worm"
	wantEntryID := uuid.New().String()
	wantChainHash := "abc123def456"

	var capturedPath string
	var capturedMethod string
	var capturedBody map[string]any

	_, client := newMockCITADEL(t, secret, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !verifyHMAC(r, raw, secret) {
			http.Error(w, "invalid HMAC", http.StatusUnauthorized)
			return
		}
		capturedPath = r.URL.Path
		capturedMethod = r.Method
		_ = json.Unmarshal(raw, &capturedBody)

		respondJSON(w, http.StatusOK, map[string]string{
			"worm_entry_id": wantEntryID,
			"chain_hash":    wantChainHash,
		})
	})

	entryID, chainHash, err := client.EmitWORM(
		context.Background(), "apiguard", "scan.started", "proj-42",
		map[string]any{"total_findings": 5},
	)
	if err != nil {
		t.Fatalf("EmitWORM returned error: %v", err)
	}
	if entryID != wantEntryID {
		t.Errorf("entryID = %q, want %q", entryID, wantEntryID)
	}
	if chainHash != wantChainHash {
		t.Errorf("chainHash = %q, want %q", chainHash, wantChainHash)
	}
	if capturedPath != "/api/v1/worm/emit" {
		t.Errorf("path = %q, want /api/v1/worm/emit", capturedPath)
	}
	if capturedMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", capturedMethod)
	}
	if capturedBody["source"] != "apiguard" {
		t.Errorf("source = %v, want apiguard", capturedBody["source"])
	}
	if capturedBody["event_type"] != "scan.started" {
		t.Errorf("event_type = %v, want scan.started", capturedBody["event_type"])
	}
	if capturedBody["project_id"] != "proj-42" {
		t.Errorf("project_id = %v, want proj-42", capturedBody["project_id"])
	}
}

// ---------------------------------------------------------------------------
// 5. EmitWORM — Chain Continuity
// ---------------------------------------------------------------------------

func TestIntegration_EmitWORM_ChainContinuity(t *testing.T) {
	const secret = "test-secret-chain"
	var callCount int32

	_, client := newMockCITADEL(t, secret, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !verifyHMAC(r, raw, secret) {
			http.Error(w, "invalid HMAC", http.StatusUnauthorized)
			return
		}

		n := atomic.AddInt32(&callCount, 1)
		switch n {
		case 1:
			respondJSON(w, http.StatusOK, map[string]string{
				"worm_entry_id": uuid.New().String(),
				"chain_hash":    "abc123",
				"prev_hash":     "",
			})
		case 2:
			respondJSON(w, http.StatusOK, map[string]string{
				"worm_entry_id": uuid.New().String(),
				"chain_hash":    "def456",
				"prev_hash":     "abc123",
			})
		default:
			http.Error(w, "unexpected call", http.StatusInternalServerError)
		}
	})

	// First call — establishes chain.
	_, chainHash1, err := client.EmitWORM(context.Background(), "apiguard", "scan.started", "p1", nil)
	if err != nil {
		t.Fatalf("first EmitWORM: %v", err)
	}
	if chainHash1 != "abc123" {
		t.Errorf("first chain_hash = %q, want %q", chainHash1, "abc123")
	}

	// Second call — continues chain.
	_, chainHash2, err := client.EmitWORM(context.Background(), "apiguard", "scan.completed", "p1", nil)
	if err != nil {
		t.Fatalf("second EmitWORM: %v", err)
	}
	if chainHash2 != "def456" {
		t.Errorf("second chain_hash = %q, want %q", chainHash2, "def456")
	}

	// Verify both calls were made.
	if got := atomic.LoadInt32(&callCount); got != 2 {
		t.Errorf("expected 2 calls, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// 6. HMAC Verification
// ---------------------------------------------------------------------------

func TestIntegration_HMAC_Verification(t *testing.T) {
	const correctSecret = "correct-secret"

	// The mock server performs strict HMAC verification and returns 401 on mismatch.
	handler := func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !verifyHMAC(r, raw, correctSecret) {
			http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
			return
		}
		respondJSON(w, http.StatusOK, citadel.Decision{
			Outcome:     citadel.OutcomeExecute,
			ExecutionID: uuid.New(),
		})
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(ts.Close)

	t.Run("correct_secret_passes", func(t *testing.T) {
		client := citadel.New(ts.URL, "test-key", correctSecret)
		decision, err := client.EvaluateScan(context.Background(), newKerkese())
		if err != nil {
			t.Fatalf("EvaluateScan with correct secret: %v", err)
		}
		if decision == nil {
			t.Fatal("expected non-nil decision with correct secret")
		}
		if decision.Outcome != citadel.OutcomeExecute {
			t.Errorf("outcome = %q, want EXECUTE", decision.Outcome)
		}
	})

	t.Run("wrong_secret_fails", func(t *testing.T) {
		client := citadel.New(ts.URL, "test-key", "wrong-secret")
		_, err := client.EvaluateScan(context.Background(), newKerkese())
		if err == nil {
			t.Fatal("expected error with wrong secret, got nil")
		}
		// The client should surface the 401 status as an error.
		if !strings.Contains(err.Error(), "401") {
			t.Errorf("error should mention 401 status, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// 7. Retry On 5xx
// ---------------------------------------------------------------------------

func TestIntegration_Retry_On5xx(t *testing.T) {
	const secret = "test-secret-retry"
	var callCount int32

	_, client := newMockCITADEL(t, secret, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !verifyHMAC(r, raw, secret) {
			http.Error(w, "invalid HMAC", http.StatusUnauthorized)
			return
		}

		n := atomic.AddInt32(&callCount, 1)
		if n <= 2 {
			// First two attempts: 500 Internal Server Error.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"transient failure"}`))
			return
		}
		// Third attempt: success.
		respondJSON(w, http.StatusOK, map[string]string{
			"worm_entry_id": uuid.New().String(),
			"chain_hash":    "retry-success-hash",
		})
	})

	entryID, chainHash, err := client.EmitWORM(
		context.Background(), "apiguard", "scan.retry", "p1", nil,
	)
	if err != nil {
		t.Fatalf("EmitWORM with retries failed: %v", err)
	}
	if entryID == "" {
		t.Error("expected non-empty entryID after retry")
	}
	if chainHash != "retry-success-hash" {
		t.Errorf("chainHash = %q, want %q", chainHash, "retry-success-hash")
	}

	total := atomic.LoadInt32(&callCount)
	if total != 3 {
		t.Errorf("expected 3 total calls (2 failures + 1 success), got %d", total)
	}
}

// ---------------------------------------------------------------------------
// 8. Full Scan Flow
// ---------------------------------------------------------------------------

func TestIntegration_FullScanFlow(t *testing.T) {
	const secret = "test-secret-fullflow"
	var mu sync.Mutex
	calls := make([]string, 0, 3)

	_, client := newMockCITADEL(t, secret, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !verifyHMAC(r, raw, secret) {
			t.Errorf("HMAC verification failed for %s %s", r.Method, r.URL.Path)
			http.Error(w, "invalid HMAC", http.StatusUnauthorized)
			return
		}

		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch r.URL.Path {
		case "/api/v1/marshal/evaluate":
			respondJSON(w, http.StatusOK, citadel.Decision{
				Outcome:     citadel.OutcomeExecute,
				ExecutionID: uuid.New(),
				TsUTC:       time.Now().UTC(),
			})
		case "/api/v1/worm/emit":
			respondJSON(w, http.StatusOK, map[string]string{
				"worm_entry_id": uuid.New().String(),
				"chain_hash":    "flow-hash-" + strconv.Itoa(len(calls)),
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	ctx := context.Background()

	// Step 1: EvaluateScan -> EXECUTE
	decision, err := client.EvaluateScan(ctx, newKerkese())
	if err != nil {
		t.Fatalf("EvaluateScan: %v", err)
	}
	if decision.Outcome != citadel.OutcomeExecute {
		t.Fatalf("expected EXECUTE, got %q", decision.Outcome)
	}

	// Step 2: EmitWORM "scan.started"
	_, _, err = client.EmitWORM(ctx, "apiguard", "scan.started", "proj-flow", map[string]any{
		"scan_id": "scan-001",
	})
	if err != nil {
		t.Fatalf("EmitWORM scan.started: %v", err)
	}

	// Step 3: EmitWORM "scan.completed"
	_, _, err = client.EmitWORM(ctx, "apiguard", "scan.completed", "proj-flow", map[string]any{
		"scan_id":        "scan-001",
		"total_findings": 7,
		"critical":       2,
	})
	if err != nil {
		t.Fatalf("EmitWORM scan.completed: %v", err)
	}

	// Verify all 3 calls were made with correct endpoints.
	mu.Lock()
	defer mu.Unlock()

	if len(calls) != 3 {
		t.Fatalf("expected 3 calls, got %d: %v", len(calls), calls)
	}
	expectedCalls := []string{
		"POST /api/v1/marshal/evaluate",
		"POST /api/v1/worm/emit",
		"POST /api/v1/worm/emit",
	}
	for i, want := range expectedCalls {
		if calls[i] != want {
			t.Errorf("call[%d] = %q, want %q", i, calls[i], want)
		}
	}
}

// ---------------------------------------------------------------------------
// 9. Disabled Mode
// ---------------------------------------------------------------------------

func TestIntegration_DisabledMode(t *testing.T) {
	var callCount int32

	// Start a real server to verify no calls are made.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	// Create client with empty baseURL — disabled mode.
	client := citadel.New("", "key", "secret")

	ctx := context.Background()

	// EvaluateScan should return nil decision, nil error.
	decision, err := client.EvaluateScan(ctx, newKerkese())
	if err != nil {
		t.Errorf("EvaluateScan on disabled client: %v", err)
	}
	if decision != nil {
		t.Errorf("expected nil decision on disabled client, got %+v", decision)
	}

	// EmitWORM should return empty strings, nil error.
	entryID, chainHash, err := client.EmitWORM(ctx, "apiguard", "scan.started", "p1", nil)
	if err != nil {
		t.Errorf("EmitWORM on disabled client: %v", err)
	}
	if entryID != "" || chainHash != "" {
		t.Errorf("expected empty strings on disabled client, got entryID=%q chainHash=%q", entryID, chainHash)
	}

	// Verify the mock server received zero calls.
	if n := atomic.LoadInt32(&callCount); n != 0 {
		t.Errorf("disabled client made %d HTTP calls, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// 10. Concurrent EmitWORM
// ---------------------------------------------------------------------------

func TestIntegration_ConcurrentEmitWORM(t *testing.T) {
	const secret = "test-secret-concurrent"
	const goroutines = 10
	var callCount int32

	_, client := newMockCITADEL(t, secret, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !verifyHMAC(r, raw, secret) {
			http.Error(w, "invalid HMAC", http.StatusUnauthorized)
			return
		}
		atomic.AddInt32(&callCount, 1)
		respondJSON(w, http.StatusOK, map[string]string{
			"worm_entry_id": uuid.New().String(),
			"chain_hash":    fmt.Sprintf("hash-%d", atomic.LoadInt32(&callCount)),
		})
	})

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			entryID, chainHash, err := client.EmitWORM(
				context.Background(),
				"apiguard",
				fmt.Sprintf("concurrent.event.%d", idx),
				"proj-concurrent",
				map[string]any{"goroutine": idx},
			)
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", idx, err)
				return
			}
			if entryID == "" {
				errs <- fmt.Errorf("goroutine %d: empty entryID", idx)
				return
			}
			if chainHash == "" {
				errs <- fmt.Errorf("goroutine %d: empty chainHash", idx)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	total := atomic.LoadInt32(&callCount)
	if total != int32(goroutines) {
		t.Errorf("expected %d calls, got %d", goroutines, total)
	}
}

// ---------------------------------------------------------------------------
// 11. Context Cancellation
// ---------------------------------------------------------------------------

func TestIntegration_ContextCancellation(t *testing.T) {
	const secret = "test-secret-ctx"

	// Mock server that takes 5 seconds to respond — simulates a slow backend.
	_, client := newMockCITADEL(t, secret, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		respondJSON(w, http.StatusOK, citadel.Decision{Outcome: citadel.OutcomeExecute})
	})

	// Cancel context after 100ms — the call must not hang for 5 seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.EvaluateScan(ctx, newKerkese())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}

	// Verify it returned quickly (well under the 5s server delay).
	if elapsed > 2*time.Second {
		t.Errorf("call took %v — context cancellation did not terminate the request promptly", elapsed)
	}

	// The error should be related to context cancellation.
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("expected context-related error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 12. NIS2 Measure Mapping
// ---------------------------------------------------------------------------

func TestIntegration_NIS2MeasureMapping(t *testing.T) {
	// All OWASP API Top 10 2023 IDs must be mapped.
	owaspIDs := []string{
		"API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023",
		"API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023",
	}

	for _, id := range owaspIDs {
		t.Run(id, func(t *testing.T) {
			measure, ok := citadel.NIS2Measure[id]
			if !ok {
				t.Fatalf("NIS2Measure missing entry for %q", id)
			}
			if measure == "" {
				t.Errorf("NIS2Measure[%q] is empty", id)
			}
			// Measure codes should be single letters a-j per NIS2 Article 21(2).
			if len(measure) != 1 || measure[0] < 'a' || measure[0] > 'j' {
				t.Errorf("NIS2Measure[%q] = %q, want a single letter a-j", id, measure)
			}
		})
	}
}
