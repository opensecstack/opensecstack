package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/ratelimit"
)

type recordingSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingSink) Record(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func newTestRateLimitAdmin(t *testing.T) (*RateLimitAdminHandler, *recordingSink, *ratelimit.Limiter, *ratelimit.MemoryOverrideStore) {
	t.Helper()
	store := ratelimit.NewMemoryOverrideStore()
	lim := ratelimit.New(ratelimit.Config{RPS: 100, Burst: 100})
	t.Cleanup(lim.Stop)
	sink := &recordingSink{}
	logger := zerolog.Nop()
	h := NewRateLimitAdminHandler(store, lim, sink, &logger)
	return h, sink, lim, store
}

func TestRateLimitAdmin_CreateRefreshesLimiter(t *testing.T) {
	h, sink, lim, store := newTestRateLimitAdmin(t)

	body := `{"kind":"sub","value":"abuser","rps":0,"burst":0,"reason":"abuse"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/ratelimit/overrides", bytes.NewBufferString(body))
	rw := httptest.NewRecorder()
	h.Create(rw, req)

	if rw.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rw.Code, rw.Body.String())
	}
	// Persisted in the store.
	list, _ := store.List(context.Background())
	if len(list) != 1 || list[0].Value != "abuser" {
		t.Fatalf("store contents = %+v", list)
	}
	// Limiter snapshot reflects the override → Allow on the matching
	// key returns false because burst=0.
	if lim.Allow("sub:abuser") {
		t.Fatal("limiter snapshot did not pick up the override (Allow returned true)")
	}
	if len(sink.events) != 1 || sink.events[0].Action != "RATELIMIT_OVERRIDE_ADD" {
		t.Fatalf("audit events = %+v", sink.events)
	}
	// Metadata round-trips through audit as the full Override.
	var meta ratelimit.Override
	if err := json.Unmarshal(sink.events[0].Metadata, &meta); err != nil {
		t.Fatalf("audit metadata: %v", err)
	}
	if meta.Value != "abuser" || meta.RPS != 0 || meta.Burst != 0 {
		t.Fatalf("audit metadata payload = %+v", meta)
	}
}

func TestRateLimitAdmin_DeleteRefreshesLimiter(t *testing.T) {
	h, sink, lim, store := newTestRateLimitAdmin(t)
	ctx := context.Background()
	if err := store.Add(ctx, ratelimit.Override{Kind: "sub", Value: "abuser", RPS: 0, Burst: 0}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := lim.Refresh(ctx, store); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// Mount in chi so URL params are populated.
	r := chi.NewRouter()
	r.Delete("/api/v1/admin/ratelimit/overrides/{kind}/{value}", h.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/ratelimit/overrides/sub/abuser", nil)
	rw := httptest.NewRecorder()
	r.ServeHTTP(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rw.Code, rw.Body.String())
	}
	// Store empty + audit event present.
	list, _ := store.List(ctx)
	if len(list) != 0 {
		t.Fatalf("store still has entries: %+v", list)
	}
	if len(sink.events) != 1 || sink.events[0].Action != "RATELIMIT_OVERRIDE_REMOVE" {
		t.Fatalf("audit events = %+v", sink.events)
	}
}

func TestRateLimitAdmin_CreateValidation(t *testing.T) {
	h, _, _, _ := newTestRateLimitAdmin(t)

	cases := []struct {
		name string
		body string
		code int
	}{
		{"bad kind", `{"kind":"bogus","value":"x","rps":1,"burst":1}`, http.StatusBadRequest},
		{"missing value", `{"kind":"sub","value":"","rps":1,"burst":1}`, http.StatusBadRequest},
		{"negative rps", `{"kind":"sub","value":"x","rps":-1,"burst":1}`, http.StatusBadRequest},
		{"malformed json", `{not json`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/ratelimit/overrides", bytes.NewBufferString(tc.body))
			rw := httptest.NewRecorder()
			h.Create(rw, req)
			if rw.Code != tc.code {
				t.Fatalf("status = %d, want %d; body=%s", rw.Code, tc.code, rw.Body.String())
			}
		})
	}
}
