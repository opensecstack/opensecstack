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
	"strings"
	"testing"
	"time"
)

// signBody returns the "sha256=<hex>" HMAC-SHA256 signature for body using secret.
func signBody(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// ---------------------------------------------------------------------------
// 1. VerifySignature — valid signature
// ---------------------------------------------------------------------------

func TestVerifySignature_Valid(t *testing.T) {
	secret := "supersecret"
	body := []byte(`{"id":"evt_001","event_type":"apiguard.scan.completed"}`)
	sig := signBody(body, secret)

	if err := VerifySignature(body, sig, secret); err != nil {
		t.Fatalf("expected nil error for valid signature, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 2. VerifySignature — wrong secret
// ---------------------------------------------------------------------------

func TestVerifySignature_WrongSecret(t *testing.T) {
	body := []byte(`{"id":"evt_002","event_type":"apiguard.scan.failed"}`)
	sig := signBody(body, "correct-secret")

	err := VerifySignature(body, sig, "wrong-secret")
	if err == nil {
		t.Fatal("expected ErrInvalidSignature, got nil")
	}
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 3. VerifySignature — tampered body
// ---------------------------------------------------------------------------

func TestVerifySignature_TamperedBody(t *testing.T) {
	secret := "mysecret"
	original := []byte(`{"id":"evt_003","event_type":"citadel.hard_stop"}`)
	sig := signBody(original, secret)

	tampered := []byte(`{"id":"evt_003","event_type":"citadel.vigil_red"}`)
	err := VerifySignature(tampered, sig, secret)
	if err == nil {
		t.Fatal("expected ErrInvalidSignature for tampered body, got nil")
	}
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 4. WebhookRouter — dispatches to the correct handler
// ---------------------------------------------------------------------------

func TestWebhookRouter_DispatchesToCorrectHandler(t *testing.T) {
	secret := "routersecret"
	var got WebhookEvent

	router := NewWebhookRouter(secret)
	router.On(EventAPIScanCompleted, func(_ context.Context, e WebhookEvent) error {
		got = e
		return nil
	})
	router.On(EventCITADELHardStop, func(_ context.Context, e WebhookEvent) error {
		t.Error("wrong handler called: hard_stop handler should not fire")
		return nil
	})

	event := WebhookEvent{
		ID:        "evt_004",
		EventType: EventAPIScanCompleted,
		Source:    "apiguard",
		Timestamp: time.Now().UTC(),
		Payload:   json.RawMessage(`{"scan_id":"scan-abc"}`),
	}
	body, _ := json.Marshal(event)
	sig := signBody(body, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(string(body)))
	req.Header.Set("X-APIGuard-Signature", sig)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got.ID != "evt_004" {
		t.Fatalf("handler received wrong event ID: got %q, want %q", got.ID, "evt_004")
	}
	if got.EventType != EventAPIScanCompleted {
		t.Fatalf("handler received wrong event type: %q", got.EventType)
	}
}

// ---------------------------------------------------------------------------
// 5. WebhookRouter — returns 400 on bad signature
// ---------------------------------------------------------------------------

func TestWebhookRouter_BadSignatureReturns400(t *testing.T) {

	router := NewWebhookRouter("the-real-secret")
	router.On(EventCITADELVigilRed, func(_ context.Context, e WebhookEvent) error {
		t.Error("handler should not be called with a bad signature")
		return nil
	})

	body := []byte(`{"id":"evt_005","event_type":"citadel.vigil_red","source":"citadel"}`)
	badSig := signBody(body, "not-the-real-secret")

	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(string(body)))
	req.Header.Set("X-Citadel-Signature", badSig)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad signature, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 6. WebhookRouter — catch-all handler fires for unregistered event types
// ---------------------------------------------------------------------------

func TestWebhookRouter_CatchAll(t *testing.T) {
	secret := "catchsecret"
	var catchedType string

	router := NewWebhookRouter(secret)
	router.On("*", func(_ context.Context, e WebhookEvent) error {
		catchedType = e.EventType
		return nil
	})

	event := WebhookEvent{
		ID:        "evt_catch",
		EventType: "some.unknown.event",
		Source:    "apiguard",
		Timestamp: time.Now().UTC(),
		Payload:   json.RawMessage(`{}`),
	}
	body, _ := json.Marshal(event)
	sig := signBody(body, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(string(body)))
	req.Header.Set("X-APIGuard-Signature", sig)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if catchedType != "some.unknown.event" {
		t.Errorf("catch-all received wrong event type: %q", catchedType)
	}
}

// ---------------------------------------------------------------------------
// 7. WebhookRouter — no handler registered returns 200 silently
// ---------------------------------------------------------------------------

func TestWebhookRouter_NoHandler_Returns200(t *testing.T) {
	secret := "nosecret"
	router := NewWebhookRouter(secret) // no handlers registered

	event := WebhookEvent{
		ID:        "evt_nohandler",
		EventType: EventNIS2ControlUpdated,
		Source:    "nis2compass",
		Timestamp: time.Now().UTC(),
		Payload:   json.RawMessage(`{}`),
	}
	body, _ := json.Marshal(event)
	sig := signBody(body, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(string(body)))
	req.Header.Set("X-Citadel-Signature", sig)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when no handler registered, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 8. WebhookRouter — handler error returns 500
// ---------------------------------------------------------------------------

func TestWebhookRouter_HandlerError_Returns500(t *testing.T) {
	secret := "errsecret"
	router := NewWebhookRouter(secret)
	router.On(EventCITADELVigilAmber, func(_ context.Context, _ WebhookEvent) error {
		return fmt.Errorf("downstream service unavailable")
	})

	event := WebhookEvent{
		ID:        "evt_err",
		EventType: EventCITADELVigilAmber,
		Source:    "citadel",
		Timestamp: time.Now().UTC(),
		Payload:   json.RawMessage(`{}`),
	}
	body, _ := json.Marshal(event)
	sig := signBody(body, secret)

	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(string(body)))
	req.Header.Set("X-Citadel-Signature", sig)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on handler error, got %d", rec.Code)
	}
}
