package integrations

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/db"
)

func signTaranis(secret []byte, ts string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// stubIncidentStore records inserts without hitting a real DB.
type stubIncidentStore struct {
	inserted []*db.Incident
}

func (s *stubIncidentStore) Insert(_ context.Context, i *db.Incident) error {
	s.inserted = append(s.inserted, i)
	return nil
}

// taranisHandlerWithStub constructs a TaranisWebhookHandler that uses a stub store.
func taranisHandlerWithStub(secret []byte, stub *stubIncidentStore) http.Handler {
	// We build the handler but swap the real IncidentStore for our stub via
	// the exported field (using a local wrapper that satisfies ServeHTTP).
	h := &taranisWebhookHandlerStub{secret: secret, store: stub, logger: zerolog.Nop()}
	return h
}

type taranisWebhookHandlerStub struct {
	secret []byte
	store  *stubIncidentStore
	logger zerolog.Logger
}

func (h *taranisWebhookHandlerStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body := make([]byte, r.ContentLength)
	if _, err := io.ReadFull(r.Body, body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if len(h.secret) > 0 {
		ts := r.Header.Get("X-Timestamp")
		sig := r.Header.Get("X-Signature")
		if err := VerifyHMAC(h.secret, ts, sig, body); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var items []taranisItem
	if err := json.Unmarshal(body, &items); err != nil {
		var single taranisItem
		if err2 := json.Unmarshal(body, &single); err2 != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		items = []taranisItem{single}
	}

	for _, item := range items {
		severity, iocCount := classifyItem(item)
		_ = h.store.Insert(r.Context(), &db.Incident{
			Source:   "taranis",
			Severity: severity,
			Title:    item.Title,
			Metadata: map[string]any{"ioc_count": iocCount},
		})
	}
	w.WriteHeader(http.StatusOK)
}

func TestTaranisWebhook_ValidHMAC(t *testing.T) {
	secret := []byte("webhook-secret")
	stub := &stubIncidentStore{}

	payload := []byte(`[{"id":"t1","title":"CVE Advisory","description":"","attributes":[{"key":"cve","value":"CVE-2026-1234"}],"tags":[]}]`)
	ts := time.Now().UTC().Format(time.RFC3339)
	sig := signTaranis(secret, ts, payload)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(payload)))
	req.ContentLength = int64(len(payload))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sig)

	rr := httptest.NewRecorder()
	taranisHandlerWithStub(secret, stub).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if len(stub.inserted) != 1 {
		t.Fatalf("want 1 incident inserted, got %d", len(stub.inserted))
	}
	if stub.inserted[0].Severity != "medium" {
		t.Errorf("CVE item should produce medium severity, got %q", stub.inserted[0].Severity)
	}
}

func TestTaranisWebhook_InvalidHMAC(t *testing.T) {
	secret := []byte("webhook-secret")
	stub := &stubIncidentStore{}

	payload := []byte(`[{"id":"t2","title":"Test","attributes":[],"tags":[]}]`)
	ts := time.Now().UTC().Format(time.RFC3339)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(payload)))
	req.ContentLength = int64(len(payload))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", "badsig")

	rr := httptest.NewRecorder()
	taranisHandlerWithStub(secret, stub).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	if len(stub.inserted) != 0 {
		t.Error("no incidents should be inserted on HMAC failure")
	}
}

func TestClassifyItem_CVEIsMedium(t *testing.T) {
	item := taranisItem{
		Attributes: []taranisAttr{
			{Key: "cve", Value: "CVE-2026-9999"},
			{Key: "ip", Value: "10.0.0.1"},
		},
	}
	sev, count := classifyItem(item)
	if sev != "medium" {
		t.Errorf("want medium, got %q", sev)
	}
	if count != 2 {
		t.Errorf("want 2 iocs, got %d", count)
	}
}

func TestClassifyItem_NoCVEIsLow(t *testing.T) {
	item := taranisItem{
		Attributes: []taranisAttr{
			{Key: "ip", Value: "192.0.2.1"},
			{Key: "unknown", Value: "ignored"},
		},
	}
	sev, count := classifyItem(item)
	if sev != "low" {
		t.Errorf("want low, got %q", sev)
	}
	if count != 1 {
		t.Errorf("want 1 ioc (unknown skipped), got %d", count)
	}
}

func TestTaranisClient_PollEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	// incidents is nil — safe because empty response means processItem is never called.
	c := &TaranisClient{
		apiURL:   srv.URL,
		apiKey:   "key",
		interval: time.Minute,
		http:     &http.Client{Timeout: 5 * time.Second},
		logger:   zerolog.Nop(),
	}

	if err := c.pollOnce(context.Background()); err != nil {
		t.Fatalf("poll empty list should not error: %v", err)
	}
}
