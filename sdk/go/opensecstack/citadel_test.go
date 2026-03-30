package opensecstack

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// citadelEventJSON builds a minimal JSON representation of a SecurityEvent.
func citadelEventJSON(id, eventType, chainHash string, payload json.RawMessage) string {
	b, _ := json.Marshal(SecurityEvent{
		ID:        id,
		EventType: eventType,
		Source:    "apiguard",
		ActorID:   "actor-1",
		ActorType: "api_key",
		ChainHash: chainHash,
		Payload:   payload,
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	return string(b)
}

// computeChainHash recomputes the expected chain hash for two consecutive
// events, mirroring the logic in VerifyChain.
func computeChainHash(prevChainHash string, payload json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(prevChainHash))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// verifySignatureHeader checks that the X-Citadel-Signature header on r
// is a valid HMAC-SHA256 of the request body under secret.
func verifySignatureHeader(t *testing.T, r *http.Request, body []byte, secret string) {
	t.Helper()
	sig := r.Header.Get("X-Citadel-Signature")
	if sig == "" {
		t.Error("X-Citadel-Signature header missing")
		return
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig != expected {
		t.Errorf("X-Citadel-Signature mismatch: got %q want %q", sig, expected)
	}
}

// ---------------------------------------------------------------------------
// Disabled-mode (empty BaseURL)
// ---------------------------------------------------------------------------

func TestCITADELClient_DisabledMode_SendEvent(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{})
	event := SecurityEvent{ID: "e-1", EventType: "test.event"}
	if err := c.SendEvent(context.Background(), event); err != nil {
		t.Errorf("SendEvent in disabled mode should return nil, got: %v", err)
	}
}

func TestCITADELClient_DisabledMode_GetEvents(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{})
	events, err := c.GetEvents(context.Background(), GetEventsOptions{})
	if err != nil {
		t.Errorf("GetEvents in disabled mode should return nil error, got: %v", err)
	}
	if events != nil {
		t.Errorf("GetEvents in disabled mode should return nil slice, got: %v", events)
	}
}

func TestCITADELClient_DisabledMode_GetEvent(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{})
	event, err := c.GetEvent(context.Background(), "e-1")
	if err != nil {
		t.Errorf("GetEvent in disabled mode should return nil error, got: %v", err)
	}
	if event != nil {
		t.Errorf("GetEvent in disabled mode should return nil event, got: %+v", event)
	}
}

func TestCITADELClient_DisabledMode_Drain(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{})
	if err := c.Drain(context.Background()); err != nil {
		t.Errorf("Drain in disabled mode should return nil, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SendEvent — event is delivered with HMAC signature
// ---------------------------------------------------------------------------

func TestCITADELClient_SendEvent_DeliveredWithSignature(t *testing.T) {
	const secret = "test-secret-key"
	var receivedBody []byte
	var receivedSig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" && r.Method == http.MethodPost {
			var buf [4096]byte
			n, _ := r.Body.Read(buf[:])
			receivedBody = buf[:n]
			receivedSig = r.Header.Get("X-Citadel-Signature")
			w.WriteHeader(http.StatusCreated)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewCITADELClient(CITADELClientOptions{
		BaseURL:       srv.URL,
		SharedSecret:  secret,
		RetryWaitBase: 1 * time.Millisecond,
	})

	event := SecurityEvent{
		ID:        "e-sig-1",
		EventType: "apiguard.scan.completed",
		Source:    "apiguard",
		ChainHash: "abc123",
		Timestamp: time.Now().UTC(),
		Payload:   json.RawMessage(`{"scan_id":"s1"}`),
	}
	if err := c.SendEvent(context.Background(), event); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}

	// Allow background worker to deliver.
	time.Sleep(100 * time.Millisecond)

	if len(receivedBody) == 0 {
		t.Fatal("server received no body")
	}

	// Verify signature.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(receivedBody)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if receivedSig != expected {
		t.Errorf("signature mismatch: got %q want %q", receivedSig, expected)
	}
}

// ---------------------------------------------------------------------------
// SendEvent — retry on 5xx
// ---------------------------------------------------------------------------

func TestCITADELClient_SendEvent_RetryOn5xx(t *testing.T) {
	var callCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/events" {
			n := atomic.AddInt32(&callCount, 1)
			if n <= 2 {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewCITADELClient(CITADELClientOptions{
		BaseURL:       srv.URL,
		SharedSecret:  "s",
		MaxRetries:    3,
		RetryWaitBase: 1 * time.Millisecond,
	})

	event := SecurityEvent{
		ID: "e-retry", EventType: "test", ChainHash: "h",
		Timestamp: time.Now(), Payload: json.RawMessage(`{}`),
	}
	if err := c.SendEvent(context.Background(), event); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	if got := atomic.LoadInt32(&callCount); got != 3 {
		t.Errorf("expected 3 delivery attempts, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// GetEvents — plain array response
// ---------------------------------------------------------------------------

func TestCITADELClient_GetEvents_PlainArray(t *testing.T) {
	payload := json.RawMessage(`{"scan_id":"s1"}`)
	events := []SecurityEvent{
		{ID: "e-1", EventType: "apiguard.scan.completed", ChainHash: "h1",
			Timestamp: time.Now(), Payload: payload},
		{ID: "e-2", EventType: "apiguard.scan.failed", ChainHash: "h2",
			Timestamp: time.Now(), Payload: payload},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}))
	defer srv.Close()

	c := NewCITADELClient(CITADELClientOptions{BaseURL: srv.URL})
	got, err := c.GetEvents(context.Background(), GetEventsOptions{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 events, got %d", len(got))
	}
	if got[0].ID != "e-1" {
		t.Errorf("unexpected first event ID: %q", got[0].ID)
	}
}

// ---------------------------------------------------------------------------
// GetEvents — paginated envelope {"items": [...]}
// ---------------------------------------------------------------------------

func TestCITADELClient_GetEvents_Envelope(t *testing.T) {
	payload := json.RawMessage(`{}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"items": []SecurityEvent{
				{ID: "e-env-1", EventType: "test", ChainHash: "h",
					Timestamp: time.Now(), Payload: payload},
			},
			"total": 1,
			"page":  1,
		})
	}))
	defer srv.Close()

	c := NewCITADELClient(CITADELClientOptions{BaseURL: srv.URL})
	got, err := c.GetEvents(context.Background(), GetEventsOptions{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(got) != 1 || got[0].ID != "e-env-1" {
		t.Errorf("unexpected events: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// GetEvents — filter query parameters are forwarded
// ---------------------------------------------------------------------------

func TestCITADELClient_GetEvents_FilterParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("source") != "apiguard" {
			http.Error(w, "missing source filter", http.StatusBadRequest)
			return
		}
		if q.Get("event_type") != "apiguard.scan.completed" {
			http.Error(w, "missing event_type filter", http.StatusBadRequest)
			return
		}
		if q.Get("limit") != "10" {
			http.Error(w, "missing limit", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[]")
	}))
	defer srv.Close()

	c := NewCITADELClient(CITADELClientOptions{BaseURL: srv.URL})
	_, err := c.GetEvents(context.Background(), GetEventsOptions{
		Source:    "apiguard",
		EventType: "apiguard.scan.completed",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("GetEvents with filters: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetEvent — by ID
// ---------------------------------------------------------------------------

func TestCITADELClient_GetEvent_ByID(t *testing.T) {
	wantEvent := SecurityEvent{
		ID:        "e-specific",
		EventType: "citadel.hard_stop",
		ChainHash: "deadbeef",
		Timestamp: time.Now().UTC().Truncate(time.Second),
		Payload:   json.RawMessage(`{"decision":"HARD_STOP"}`),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events/e-specific" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(wantEvent)
	}))
	defer srv.Close()

	c := NewCITADELClient(CITADELClientOptions{BaseURL: srv.URL})
	got, err := c.GetEvent(context.Background(), "e-specific")
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	if got.ID != wantEvent.ID {
		t.Errorf("unexpected event ID: got %q want %q", got.ID, wantEvent.ID)
	}
}

func TestCITADELClient_GetEvent_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewCITADELClient(CITADELClientOptions{BaseURL: srv.URL})
	_, err := c.GetEvent(context.Background(), "no-such-event")
	if err == nil {
		t.Fatal("expected an error for 404, got nil")
	}
}

func TestCITADELClient_GetEvent_EmptyID(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{BaseURL: "http://unused"})
	_, err := c.GetEvent(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty event ID")
	}
}

// ---------------------------------------------------------------------------
// VerifyChain — valid chain
// ---------------------------------------------------------------------------

func TestCITADELClient_VerifyChain_Valid(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{})

	// Build a 3-event chain with correct hashes.
	genesis := "0000000000000000000000000000000000000000000000000000000000000000"
	p0 := json.RawMessage(`{"seq":0}`)
	h0 := computeChainHash(genesis, p0)

	p1 := json.RawMessage(`{"seq":1}`)
	h1 := computeChainHash(h0, p1)

	p2 := json.RawMessage(`{"seq":2}`)
	h2 := computeChainHash(h1, p2)

	events := []SecurityEvent{
		{ID: "e0", ChainHash: h0, Payload: p0, Timestamp: time.Now()},
		{ID: "e1", ChainHash: h1, Payload: p1, Timestamp: time.Now()},
		{ID: "e2", ChainHash: h2, Payload: p2, Timestamp: time.Now()},
	}

	if err := c.VerifyChain(context.Background(), events); err != nil {
		t.Errorf("VerifyChain: unexpected error on valid chain: %v", err)
	}
}

func TestCITADELClient_VerifyChain_SingleEvent_OK(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{})
	events := []SecurityEvent{{ID: "e0", ChainHash: "any", Payload: json.RawMessage(`{}`)}}
	if err := c.VerifyChain(context.Background(), events); err != nil {
		t.Errorf("VerifyChain single event: unexpected error: %v", err)
	}
}

func TestCITADELClient_VerifyChain_EmptySlice_OK(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{})
	if err := c.VerifyChain(context.Background(), nil); err != nil {
		t.Errorf("VerifyChain empty slice: unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// VerifyChain — broken link
// ---------------------------------------------------------------------------

func TestCITADELClient_VerifyChain_BrokenLink(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{})

	genesis := "0000000000000000000000000000000000000000000000000000000000000000"
	p0 := json.RawMessage(`{"seq":0}`)
	h0 := computeChainHash(genesis, p0)

	p1 := json.RawMessage(`{"seq":1}`)
	// Deliberately wrong hash for event 1.
	wrongH1 := "badhashbadhashbadhashbadhashbadhashbadhashbadhashbadhashbadhash"

	events := []SecurityEvent{
		{ID: "e0", ChainHash: h0, Payload: p0},
		{ID: "e1", ChainHash: wrongH1, Payload: p1},
	}

	err := c.VerifyChain(context.Background(), events)
	if err == nil {
		t.Fatal("VerifyChain: expected error for broken link, got nil")
	}
}

// ---------------------------------------------------------------------------
// signBody
// ---------------------------------------------------------------------------

func TestCITADELClient_SignBody(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{
		BaseURL:      "http://unused",
		SharedSecret: "my-secret",
	})
	body := []byte(`{"event_type":"test"}`)
	sig := c.signBody(body)
	if len(sig) == 0 {
		t.Fatal("signBody returned empty string")
	}
	if sig[:7] != "sha256=" {
		t.Errorf("signature should start with sha256=, got: %q", sig)
	}
	// Verify the HMAC value independently.
	mac := hmac.New(sha256.New, []byte("my-secret"))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig != expected {
		t.Errorf("signBody mismatch: got %q want %q", sig, expected)
	}
}
