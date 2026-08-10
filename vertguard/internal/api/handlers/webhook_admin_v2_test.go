package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	vgwebhook "github.com/opensecstack/vertguard/internal/webhook"
)

// storeWithNilPool builds a real *vgwebhook.Store whose internal Pool
// is nil. The store's own methods guard on a nil pool and return a
// plain error rather than panicking (see internal/webhook/store.go),
// so this exercises every handler branch downstream of "store is
// configured" without needing a live Postgres connection.
func storeWithNilPool() *vgwebhook.Store {
	return vgwebhook.NewStore(nil)
}

func TestWebhookCreateV2_MalformedJSON_Returns400(t *testing.T) {
	h := &WebhookSubscribersHandler{Store: storeWithNilPool()}
	r := httptest.NewRequest(http.MethodPost, "/webhook/subscribers", bytes.NewReader([]byte("{bad")))
	w := httptest.NewRecorder()
	h.CreateV2(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookCreateV2_MissingFields_Returns400(t *testing.T) {
	h := &WebhookSubscribersHandler{Store: storeWithNilPool()}
	body, _ := json.Marshal(map[string]string{"url": "https://example.com/hook"}) // no hmac_secret
	r := httptest.NewRequest(http.MethodPost, "/webhook/subscribers", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateV2(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookCreateV2_ValidBody_StoreFailure_Returns500(t *testing.T) {
	// Store is configured (non-nil) but its pool is nil, so Upsert must
	// fail — this is the real "store_failed" branch, distinct from the
	// "store not configured" 503.
	h := &WebhookSubscribersHandler{Store: storeWithNilPool()}
	body, _ := json.Marshal(map[string]string{
		"url":         "https://example.com/hook",
		"hmac_secret": "s3cret",
	})
	r := httptest.NewRequest(http.MethodPost, "/webhook/subscribers", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateV2(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("store_failed")) {
		t.Errorf("body=%s, want store_failed code", w.Body.String())
	}
}

func TestWebhookListV2_NilPoolStore_ReturnsEmptyList(t *testing.T) {
	// Store.List() with a nil pool returns (nil, nil) rather than an
	// error (see internal/webhook/store.go) — the handler must surface
	// that as a 200 with an empty array, not a 500.
	h := &WebhookSubscribersHandler{Store: storeWithNilPool()}
	w := httptest.NewRecorder()
	h.ListV2(w, httptest.NewRequest(http.MethodGet, "/webhook/subscribers", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Subscribers []vgwebhook.PublicView `json:"subscribers"`
		Count       int                    `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 0 || len(resp.Subscribers) != 0 {
		t.Fatalf("unexpected non-empty list: %+v", resp)
	}
}

func TestWebhookDeleteV2_InvalidUUID_WithStore_Returns400(t *testing.T) {
	h := &WebhookSubscribersHandler{Store: storeWithNilPool()}
	r := withIDParam(httptest.NewRequest(http.MethodDelete, "/webhook/subscribers/not-a-uuid", nil), "not-a-uuid")
	w := httptest.NewRecorder()
	h.DeleteV2(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookDeleteV2_ValidUUID_StoreFailure_Returns500(t *testing.T) {
	h := &WebhookSubscribersHandler{Store: storeWithNilPool()}
	id := uuid.NewString()
	r := withIDParam(httptest.NewRequest(http.MethodDelete, "/webhook/subscribers/"+id, nil), id)
	w := httptest.NewRecorder()
	h.DeleteV2(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookRotateV2_InvalidUUID_WithStore_Returns400(t *testing.T) {
	h := &WebhookSubscribersHandler{Store: storeWithNilPool()}
	body, _ := json.Marshal(map[string]string{"new_secret": "s2"})
	r := withIDParam(httptest.NewRequest(http.MethodPost, "/webhook/subscribers/not-a-uuid/rotate", bytes.NewReader(body)), "not-a-uuid")
	w := httptest.NewRecorder()
	h.Rotate(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookRotateV2_MalformedJSON_Returns400(t *testing.T) {
	h := &WebhookSubscribersHandler{Store: storeWithNilPool()}
	id := uuid.NewString()
	r := withIDParam(httptest.NewRequest(http.MethodPost, "/webhook/subscribers/"+id+"/rotate", bytes.NewReader([]byte("{bad"))), id)
	w := httptest.NewRecorder()
	h.Rotate(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestWebhookRotateV2_MissingNewSecret_Returns400(t *testing.T) {
	h := &WebhookSubscribersHandler{Store: storeWithNilPool()}
	id := uuid.NewString()
	body, _ := json.Marshal(map[string]string{"new_key_id": "k2"})
	r := withIDParam(httptest.NewRequest(http.MethodPost, "/webhook/subscribers/"+id+"/rotate", bytes.NewReader(body)), id)
	w := httptest.NewRecorder()
	h.Rotate(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("missing_field")) {
		t.Errorf("body=%s, want missing_field code", w.Body.String())
	}
}

func TestWebhookRotateV2_ValidRequest_PropagatesStoreFailure(t *testing.T) {
	// Rotate's Get() call fails first on a nil pool -> "nil pool" error,
	// which is not ErrNotFound, so the handler must map it to 500
	// rotate_failed (not 404).
	h := &WebhookSubscribersHandler{Store: storeWithNilPool()}
	id := uuid.NewString()
	body, _ := json.Marshal(map[string]string{"new_secret": "s2", "new_key_id": "k2"})
	r := withIDParam(httptest.NewRequest(http.MethodPost, "/webhook/subscribers/"+id+"/rotate", bytes.NewReader(body)), id)
	w := httptest.NewRecorder()
	h.Rotate(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("rotate_failed")) {
		t.Errorf("body=%s, want rotate_failed code", w.Body.String())
	}
}
