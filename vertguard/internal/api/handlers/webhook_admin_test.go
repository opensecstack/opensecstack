package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/threatfeed/webhook"
)

func newPublisherHandler() *WebhookAdminHandler {
	pub := webhook.New(zerolog.Nop(), nil, nil)
	return NewWebhookAdminHandler(pub)
}

func withIDParam(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// ─── Legacy in-memory Publisher handler ────────────────────────────

func TestWebhookCreate_MissingFields_Returns400(t *testing.T) {
	h := newPublisherHandler()
	body, _ := json.Marshal(map[string]string{"url": "https://example.com/hook"}) // no hmac_secret
	r := httptest.NewRequest(http.MethodPost, "/webhooks/subscribers", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Create(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookCreate_MalformedJSON_Returns400(t *testing.T) {
	h := newPublisherHandler()
	r := httptest.NewRequest(http.MethodPost, "/webhooks/subscribers", bytes.NewReader([]byte("{bad")))
	w := httptest.NewRecorder()
	h.Create(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

// TestWebhookCreate_NeverLeaksSecret is a security-relevant regression
// guard: the HMAC secret must never appear in the API response, even
// though it was just accepted on the request.
func TestWebhookCreate_NeverLeaksSecret(t *testing.T) {
	h := newPublisherHandler()
	body, _ := json.Marshal(map[string]string{
		"url":         "https://example.com/hook",
		"hmac_secret": "super-secret-value",
	})
	r := httptest.NewRequest(http.MethodPost, "/webhooks/subscribers", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Create(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("super-secret-value")) {
		t.Fatalf("response leaked the HMAC secret: %s", w.Body.String())
	}
}

func TestWebhookCreate_DefaultsActiveTrue(t *testing.T) {
	h := newPublisherHandler()
	body, _ := json.Marshal(map[string]string{
		"url":         "https://example.com/hook",
		"hmac_secret": "s3cret",
	})
	r := httptest.NewRequest(http.MethodPost, "/webhooks/subscribers", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Create(w, r)
	var resp webhook.Subscriber
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Active {
		t.Error("Active = false, want default true when omitted")
	}
}

func TestWebhookCreate_ExplicitActiveFalse_Respected(t *testing.T) {
	h := newPublisherHandler()
	body, _ := json.Marshal(map[string]any{
		"url":         "https://example.com/hook",
		"hmac_secret": "s3cret",
		"active":      false,
	})
	r := httptest.NewRequest(http.MethodPost, "/webhooks/subscribers", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Create(w, r)
	var resp webhook.Subscriber
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Active {
		t.Error("Active = true, want explicit false to be respected")
	}
}

func TestWebhookList_ReturnsCreatedSubscribers(t *testing.T) {
	h := newPublisherHandler()
	body, _ := json.Marshal(map[string]string{"url": "https://example.com/hook", "hmac_secret": "s"})
	h.Create(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/webhooks/subscribers", bytes.NewReader(body)))

	w := httptest.NewRecorder()
	h.List(w, httptest.NewRequest(http.MethodGet, "/webhooks/subscribers", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var subs []webhook.Subscriber
	if err := json.Unmarshal(w.Body.Bytes(), &subs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("len(subs) = %d, want 1", len(subs))
	}
}

func TestWebhookDelete_MissingID_Returns400(t *testing.T) {
	h := newPublisherHandler()
	r := withIDParam(httptest.NewRequest(http.MethodDelete, "/webhooks/subscribers/", nil), "")
	w := httptest.NewRecorder()
	h.Delete(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestWebhookDelete_UnknownID_Returns404(t *testing.T) {
	h := newPublisherHandler()
	r := withIDParam(httptest.NewRequest(http.MethodDelete, "/webhooks/subscribers/nope", nil), "nope")
	w := httptest.NewRecorder()
	h.Delete(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestWebhookDelete_KnownID_Returns204(t *testing.T) {
	h := newPublisherHandler()
	body, _ := json.Marshal(map[string]string{"url": "https://example.com/hook", "hmac_secret": "s"})
	cw := httptest.NewRecorder()
	h.Create(cw, httptest.NewRequest(http.MethodPost, "/webhooks/subscribers", bytes.NewReader(body)))
	var created webhook.Subscriber
	_ = json.Unmarshal(cw.Body.Bytes(), &created)

	r := withIDParam(httptest.NewRequest(http.MethodDelete, "/webhooks/subscribers/"+created.ID, nil), created.ID)
	w := httptest.NewRecorder()
	h.Delete(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d body=%s", w.Code, w.Body.String())
	}
}

// ─── VG-015 DB-backed handler: nil-store and validation guards ───────
// (No live DB in this test environment — only paths that short-circuit
// before touching the store are exercised here.)

func TestWebhookCreateV2_NilStore_Returns503(t *testing.T) {
	h := &WebhookSubscribersHandler{} // Store deliberately nil
	body, _ := json.Marshal(map[string]string{"url": "https://example.com/hook", "hmac_secret": "s"})
	r := httptest.NewRequest(http.MethodPost, "/webhook/subscribers", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateV2(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookListV2_NilStore_Returns503(t *testing.T) {
	h := &WebhookSubscribersHandler{}
	w := httptest.NewRecorder()
	h.ListV2(w, httptest.NewRequest(http.MethodGet, "/webhook/subscribers", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookDeleteV2_NilStore_Returns503(t *testing.T) {
	h := &WebhookSubscribersHandler{}
	r := withIDParam(httptest.NewRequest(http.MethodDelete, "/webhook/subscribers/"+uuid.NewString(), nil), uuid.NewString())
	w := httptest.NewRecorder()
	h.DeleteV2(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookRotateV2_NilStore_Returns503(t *testing.T) {
	h := &WebhookSubscribersHandler{}
	body, _ := json.Marshal(map[string]string{"new_secret": "s2"})
	r := withIDParam(httptest.NewRequest(http.MethodPost, "/webhook/subscribers/x/rotate", bytes.NewReader(body)), uuid.NewString())
	w := httptest.NewRecorder()
	h.Rotate(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestWebhookCreateV2_MissingFields exercises validation that runs
// even with a nil store — it must fail with 503 (store check happens
// first) rather than accidentally validating first. This documents
// actual precedence: store-availability is checked before body
// validation.
func TestWebhookDeleteV2_InvalidUUID_RequiresStore(t *testing.T) {
	// With Store nil, the 503 guard fires before UUID parsing — this
	// test documents that precedence explicitly rather than assuming it.
	h := &WebhookSubscribersHandler{}
	r := withIDParam(httptest.NewRequest(http.MethodDelete, "/webhook/subscribers/not-a-uuid", nil), "not-a-uuid")
	w := httptest.NewRecorder()
	h.DeleteV2(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 (store checked before UUID parsing), got %d", w.Code)
	}
}
