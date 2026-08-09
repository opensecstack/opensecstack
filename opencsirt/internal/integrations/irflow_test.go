package integrations

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/incident"
)

func signIRFlow(secret []byte, ts string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func TestNewIRFlowWebhook_SetsFields(t *testing.T) {
	svc := incident.New(nil, nil, nil, zerolog.Nop())
	h := NewIRFlowWebhook(IRFlowConfig{Secret: "s3cr3t", StrictSeverity: true}, svc, zerolog.Nop())
	if h == nil {
		t.Fatal("NewIRFlowWebhook returned nil")
	}
	if string(h.secret) != "s3cr3t" {
		t.Errorf("secret = %q, want s3cr3t", h.secret)
	}
	if !h.strictSeverity {
		t.Error("strictSeverity should be true")
	}
}

func TestIRFlowWebhook_ServeHTTP_InvalidHMACReturns401(t *testing.T) {
	svc := incident.New(nil, nil, nil, zerolog.Nop())
	h := NewIRFlowWebhook(IRFlowConfig{Secret: "s3cr3t"}, svc, zerolog.Nop())

	payload := []byte(`{"id":"i1","severity":"high","title":"t"}`)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(payload)))
	req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("X-Signature", "wrong")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rr.Code)
	}
}

func TestIRFlowWebhook_ServeHTTP_InvalidJSONReturns400(t *testing.T) {
	secret := []byte("s3cr3t")
	svc := incident.New(nil, nil, nil, zerolog.Nop())
	h := NewIRFlowWebhook(IRFlowConfig{Secret: string(secret)}, svc, zerolog.Nop())

	payload := []byte("{not json")
	ts := time.Now().UTC().Format(time.RFC3339)
	sig := signIRFlow(secret, ts, payload)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(payload)))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sig)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestIRFlowWebhook_ServeHTTP_StrictSeverityRejectsUnrecognisedSeverity(t *testing.T) {
	secret := []byte("s3cr3t")
	// svc left as a real Service backed by nil stores: StrictSeverity must
	// reject before ever calling svc.Create, or this test panics.
	svc := incident.New(nil, nil, nil, zerolog.Nop())
	h := NewIRFlowWebhook(IRFlowConfig{Secret: string(secret), StrictSeverity: true}, svc, zerolog.Nop())

	payload := []byte(`{"id":"i1","severity":"weird","title":"t"}`)
	ts := time.Now().UTC().Format(time.RFC3339)
	sig := signIRFlow(secret, ts, payload)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(payload)))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sig)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unrecognised severity") {
		t.Errorf("body = %q, want it to mention unrecognised severity", rr.Body.String())
	}
}

func TestIRFlowWebhook_ServeHTTP_NonStrictCoercesAndEmptyTitleSurfacesAsBadRequest(t *testing.T) {
	secret := []byte("s3cr3t")
	// Empty title must be rejected by incident.Service.Create's own
	// validation (ErrEmptyTitle) before it ever reaches the nil store —
	// exercising the real Service end-to-end for this error path.
	svc := incident.New(nil, nil, nil, zerolog.Nop())
	h := NewIRFlowWebhook(IRFlowConfig{Secret: string(secret), StrictSeverity: false}, svc, zerolog.Nop())

	payload := []byte(`{"id":"i1","severity":"weird","title":""}`)
	ts := time.Now().UTC().Format(time.RFC3339)
	sig := signIRFlow(secret, ts, payload)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(payload)))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sig)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestIRFlowWebhook_Run_IsNoOpAndReturnsImmediately(t *testing.T) {
	h := NewIRFlowWebhook(IRFlowConfig{Secret: "s"}, nil, zerolog.Nop())
	done := make(chan struct{})
	go func() {
		h.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run should return immediately (no-op)")
	}
}
