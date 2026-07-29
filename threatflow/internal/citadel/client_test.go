package citadel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func TestClient_NoopWhenBaseURLEmpty(t *testing.T) {
	c := New(Config{}, zerolog.Nop())
	if c.Enabled() {
		t.Fatal("empty base url should produce a no-op client")
	}

	d, err := c.Evaluate(context.Background(), ActionIOCIngest, "", "user-1", "", "admin", "")
	if err != nil {
		t.Fatalf("no-op evaluate: %v", err)
	}
	if !d.Allowed() {
		t.Errorf("no-op evaluate should EXECUTE, got %s", d.Outcome)
	}

	if err := c.Emit(context.Background(), "threatflow", "test", nil); err != nil {
		t.Errorf("no-op emit: %v", err)
	}
}

func TestClient_Evaluate_SignedRequest(t *testing.T) {
	const (
		key    = "k1"
		secret = "topsecret"
	)
	var captured struct {
		sig  string
		ts   string
		body []byte
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.sig = r.Header.Get("X-CITADEL-SIG")
		captured.ts = r.Header.Get("X-CITADEL-TS")
		captured.body, _ = io.ReadAll(r.Body)

		_ = json.NewEncoder(w).Encode(Decision{
			Outcome:     OutcomeExecute,
			ExecutionID: uuid.New(),
			TsUTC:       time.Now().UTC(),
		})
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, KeyID: key, Secret: secret}, zerolog.Nop())
	d, err := c.Evaluate(context.Background(), ActionIOCIngest, "test", "user-1", "a@b.c", "admin", "test-bearer-token")
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if d.Outcome != OutcomeExecute {
		t.Errorf("outcome = %s", d.Outcome)
	}

	// Recompute expected signature and compare.
	bodyHash := sha256.Sum256(captured.body)
	msg := key + ":" + captured.ts + ":" + hex.EncodeToString(bodyHash[:])
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	want := "hmac-sha256=" + hex.EncodeToString(mac.Sum(nil))
	if captured.sig != want {
		t.Errorf("signature mismatch\nwant %s\ngot  %s", want, captured.sig)
	}
	// Timestamp should be a recent unix seconds value.
	ts, _ := strconv.ParseInt(captured.ts, 10, 64)
	if diff := time.Since(time.Unix(ts, 0)); diff < 0 || diff > 10*time.Second {
		t.Errorf("timestamp %s skewed by %v", captured.ts, diff)
	}

	// The Kerkese sent over the wire must carry a non-empty, non-zero-value
	// Actor.UserID/SoD.OperatorUserID (the caller's real identity), the
	// forwarded ActorToken, and a Verifier distinct from the Actor so Gate 3's
	// NDS_SAME_IDENTITY HARD_STOP never trips on ThreatFlow's placeholder
	// verifier flow (see citadel adrs/005-sinauth-identity-bridge.md).
	var sent Kerkese
	if err := json.Unmarshal(captured.body, &sent); err != nil {
		t.Fatalf("unmarshal sent kerkese: %v", err)
	}
	if sent.Actor.UserID != "user-1" {
		t.Errorf("Actor.UserID = %q, want %q", sent.Actor.UserID, "user-1")
	}
	if sent.SoD.OperatorUserID != "user-1" {
		t.Errorf("SoD.OperatorUserID = %q, want %q", sent.SoD.OperatorUserID, "user-1")
	}
	if sent.ActorToken != "test-bearer-token" {
		t.Errorf("ActorToken = %q, want %q", sent.ActorToken, "test-bearer-token")
	}
	if sent.Verifier.UserID == "" || sent.Verifier.UserID == sent.Actor.UserID {
		t.Errorf("Verifier.UserID = %q, must be non-empty and distinct from Actor.UserID %q", sent.Verifier.UserID, sent.Actor.UserID)
	}
	if sent.SoD.VerifierUserID != sent.Verifier.UserID {
		t.Errorf("SoD.VerifierUserID = %q, want %q", sent.SoD.VerifierUserID, sent.Verifier.UserID)
	}
	if sent.VerifierToken != "" {
		t.Errorf("VerifierToken = %q, want empty (no real second-approver identity)", sent.VerifierToken)
	}
}

func TestClient_Evaluate_FailClosed(t *testing.T) {
	// Server never accepts the connection → dial error → fail-closed path.
	c := New(Config{BaseURL: "http://127.0.0.1:1", Secret: "x", KeyID: "x", FailMode: FailClosed}, zerolog.Nop())
	d, err := c.Evaluate(context.Background(), ActionIOCIngest, "", "user-1", "", "admin", "")
	if err != nil {
		t.Fatalf("evaluate returned err: %v", err)
	}
	if d.Outcome != OutcomeRefuse {
		t.Errorf("fail-closed should REFUSE, got %s", d.Outcome)
	}
}

func TestClient_Evaluate_FailOpen(t *testing.T) {
	c := New(Config{BaseURL: "http://127.0.0.1:1", Secret: "x", KeyID: "x", FailMode: FailOpen}, zerolog.Nop())
	d, err := c.Evaluate(context.Background(), ActionIOCIngest, "", "user-1", "", "admin", "")
	if err != nil {
		t.Fatalf("evaluate returned err: %v", err)
	}
	if d.Outcome != OutcomeExecute {
		t.Errorf("fail-open should EXECUTE, got %s", d.Outcome)
	}
}

func TestClient_EmitAsync_DrainWaitsForInFlight(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"worm_entry_id": uuid.NewString(),
			"chain_hash":    "aaaa",
			"prev_hash":     "",
		})
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, KeyID: "k", Secret: "s"}, zerolog.Nop())
	for i := 0; i < 5; i++ {
		c.EmitAsync("threatflow", "test.event", map[string]any{"n": i})
	}
	drainCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.Drain(drainCtx)

	if got := atomic.LoadInt32(&received); got != 5 {
		t.Errorf("want 5 emissions, got %d", got)
	}
}
