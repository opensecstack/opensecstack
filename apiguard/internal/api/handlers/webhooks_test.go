package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

const testWebhookSecret = "test-webhook-secret-key"

// signBody computes the HMAC-SHA256 signature for a body using the given secret
// and returns the header value in "sha256=<hex>" format.
func signBody(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func makeWebhookEvent(eventType string) []byte {
	event := map[string]interface{}{
		"event_type": eventType,
		"payload":    map[string]string{"detail": "test"},
		"timestamp":  "2026-03-31T12:00:00Z",
	}
	b, _ := json.Marshal(event)
	return b
}

func TestCITADELWebhook_ValidSignature_200(t *testing.T) {
	logger := zerolog.Nop()
	wh := NewWebhooks(logger, testWebhookSecret, nil)

	body := makeWebhookEvent("citadel.vigil_amber")
	sig := signBody(body, testWebhookSecret)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", sig)
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCITADELWebhook_InvalidSignature_401(t *testing.T) {
	logger := zerolog.Nop()
	wh := NewWebhooks(logger, testWebhookSecret, nil)

	body := makeWebhookEvent("citadel.vigil_amber")
	wrongSig := signBody(body, "wrong-secret")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", wrongSig)
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCITADELWebhook_MissingSignature_401(t *testing.T) {
	logger := zerolog.Nop()
	wh := NewWebhooks(logger, testWebhookSecret, nil)

	body := makeWebhookEvent("citadel.vigil_amber")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No X-Webhook-Signature header.
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCITADELWebhook_HardStop_Logged(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	wh := NewWebhooks(logger, testWebhookSecret, nil)

	body := makeWebhookEvent("citadel.hard_stop")
	sig := signBody(body, testWebhookSecret)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", sig)
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	logOutput := buf.String()
	if logOutput == "" {
		t.Fatal("expected log output for hard_stop event, got nothing")
	}
	// Verify the log contains CRITICAL-level messaging.
	if !bytes.Contains(buf.Bytes(), []byte("hard_stop")) {
		t.Errorf("log output should mention hard_stop; got: %s", logOutput)
	}
}

func TestCITADELWebhook_VIGILRed_Logged(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	wh := NewWebhooks(logger, testWebhookSecret, nil)

	body := makeWebhookEvent("citadel.vigil_red")
	sig := signBody(body, testWebhookSecret)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", sig)
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	logOutput := buf.String()
	if logOutput == "" {
		t.Fatal("expected log output for vigil_red event, got nothing")
	}
	if !bytes.Contains(buf.Bytes(), []byte("vigil_red")) {
		t.Errorf("log output should mention vigil_red; got: %s", logOutput)
	}
}

func TestCITADELWebhook_UnknownEvent_200(t *testing.T) {
	logger := zerolog.Nop()
	wh := NewWebhooks(logger, testWebhookSecret, nil)

	body := makeWebhookEvent("citadel.some_future_event")
	sig := signBody(body, testWebhookSecret)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", sig)
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 for unknown event, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCITADELWebhook_MalformedBody_400(t *testing.T) {
	logger := zerolog.Nop()
	wh := NewWebhooks(logger, testWebhookSecret, nil)

	body := []byte(`{this is not valid json}`)
	sig := signBody(body, testWebhookSecret)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", sig)
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestCITADELWebhook_EmptySecret_401 verifies that if the server has no
// webhook secret configured, all requests are rejected.
func TestCITADELWebhook_EmptySecret_401(t *testing.T) {
	logger := zerolog.Nop()
	wh := NewWebhooks(logger, "", nil) // no secret configured

	body := makeWebhookEvent("citadel.vigil_amber")
	sig := signBody(body, "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", sig)
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 when no secret is configured, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestCITADELWebhook_MalformedSignatureFormat_401 verifies that a signature
// without the "sha256=" prefix is rejected.
func TestCITADELWebhook_MalformedSignatureFormat_401(t *testing.T) {
	logger := zerolog.Nop()
	wh := NewWebhooks(logger, testWebhookSecret, nil)

	body := makeWebhookEvent("citadel.vigil_amber")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", "not-sha256-format")
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for malformed signature format, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
