package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/auth/denylist"
)

func newTestDenylistAdmin(t *testing.T) (*DenylistAdminHandler, *recordingSink, *denylist.Store) {
	t.Helper()
	store := denylist.NewMemoryStore()
	var s denylist.Store = store
	cache := denylist.NewCache(store)
	sink := &recordingSink{}
	logger := zerolog.Nop()
	h := NewDenylistAdminHandler(store, cache, sink, &logger)
	return h, sink, &s
}

func TestDenylistAdmin_NilHandlerReturns503(t *testing.T) {
	var h *DenylistAdminHandler
	for _, call := range []func(http.ResponseWriter, *http.Request){h.Create, h.List, h.Delete} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		rw := httptest.NewRecorder()
		call(rw, req)
		if rw.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d, want 503", rw.Code)
		}
	}
}

func TestDenylistAdmin_Create_Success(t *testing.T) {
	h, sink, _ := newTestDenylistAdmin(t)
	body := `{"kind":"jti","value":"tok-123","reason":"compromised"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/denylist", bytes.NewBufferString(body))
	ctx := auth.InjectClaimsForTest(req.Context(), &auth.Claims{Sub: "operator1", Role: auth.RoleAdmin})
	req = req.WithContext(ctx)
	rw := httptest.NewRecorder()
	h.Create(rw, req)

	if rw.Code != http.StatusCreated {
		t.Fatalf("status=%d, want 201; body=%s", rw.Code, rw.Body.String())
	}
	var entry denylist.Entry
	if err := json.Unmarshal(rw.Body.Bytes(), &entry); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if entry.RevokedBy != "operator1" || entry.Value != "tok-123" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	if len(sink.events) != 1 || sink.events[0].Action != "REVOKE_TOKEN" {
		t.Fatalf("audit events = %+v", sink.events)
	}
	if sink.events[0].Actor != "operator1" {
		t.Fatalf("audit actor = %q, want operator1", sink.events[0].Actor)
	}

	// The cache should now know about this entry.
	revoked, reason := h.Cache.IsRevoked(&auth.Claims{Jti: "tok-123"})
	if !revoked || reason != "compromised" {
		t.Fatalf("cache not refreshed after create: revoked=%v reason=%q", revoked, reason)
	}
}

func TestDenylistAdmin_Create_NoClaimsDefaultsUnknown(t *testing.T) {
	h, sink, _ := newTestDenylistAdmin(t)
	body := `{"kind":"sub","value":"user1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/denylist", bytes.NewBufferString(body))
	rw := httptest.NewRecorder()
	h.Create(rw, req)
	if rw.Code != http.StatusCreated {
		t.Fatalf("status=%d, want 201", rw.Code)
	}
	if sink.events[0].Actor != "unknown" {
		t.Fatalf("actor = %q, want unknown", sink.events[0].Actor)
	}
}

func TestDenylistAdmin_Create_Validation(t *testing.T) {
	h, _, _ := newTestDenylistAdmin(t)
	cases := []struct {
		name string
		body string
	}{
		{"malformed json", `{bad`},
		{"bad reason too long", `{"kind":"jti","value":"x","reason":"` + string(make([]byte, 300)) + `"}`},
		{"invalid kind", `{"kind":"bogus","value":"x"}`},
		{"missing value", `{"kind":"jti","value":""}`},
		{"bad expires_at", `{"kind":"jti","value":"x","expires_at":"not-a-date"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/denylist", bytes.NewBufferString(c.body))
			rw := httptest.NewRecorder()
			h.Create(rw, req)
			if rw.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400; body=%s", rw.Code, rw.Body.String())
			}
		})
	}
}

func TestDenylistAdmin_Create_ValidExpiresAt(t *testing.T) {
	h, _, _ := newTestDenylistAdmin(t)
	body := `{"kind":"jti","value":"exp-tok","expires_at":"2030-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/denylist", bytes.NewBufferString(body))
	rw := httptest.NewRecorder()
	h.Create(rw, req)
	if rw.Code != http.StatusCreated {
		t.Fatalf("status=%d, want 201; body=%s", rw.Code, rw.Body.String())
	}
	var entry denylist.Entry
	_ = json.Unmarshal(rw.Body.Bytes(), &entry)
	if entry.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
}

func TestDenylistAdmin_List(t *testing.T) {
	h, _, storePtr := newTestDenylistAdmin(t)
	store := *storePtr
	_ = store.Add(context.Background(), denylist.Entry{Kind: denylist.KindJTI, Value: "a"})
	_ = store.Add(context.Background(), denylist.Entry{Kind: denylist.KindSub, Value: "b"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/denylist", nil)
	rw := httptest.NewRecorder()
	h.List(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rw.Code)
	}
	var resp struct {
		Entries []denylist.Entry `json:"entries"`
		Count   int              `json:"count"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 2 || len(resp.Entries) != 2 {
		t.Fatalf("unexpected list response: %+v", resp)
	}
}

func TestDenylistAdmin_Delete_Success(t *testing.T) {
	h, sink, storePtr := newTestDenylistAdmin(t)
	store := *storePtr
	_ = store.Add(context.Background(), denylist.Entry{Kind: denylist.KindJTI, Value: "del-me"})
	_ = h.Cache.Refresh(context.Background())

	r := chi.NewRouter()
	r.Delete("/api/v1/admin/denylist/{kind}/{value}", h.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/denylist/jti/del-me", nil)
	ctx := auth.InjectClaimsForTest(req.Context(), &auth.Claims{Sub: "admin2", Role: auth.RoleAdmin})
	req = req.WithContext(ctx)
	rw := httptest.NewRecorder()
	r.ServeHTTP(rw, req)

	if rw.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want 204; body=%s", rw.Code, rw.Body.String())
	}
	list, _ := store.List(context.Background())
	if len(list) != 0 {
		t.Fatalf("store still has entries: %+v", list)
	}
	if len(sink.events) != 1 || sink.events[0].Action != "UNREVOKE_TOKEN" {
		t.Fatalf("audit events = %+v", sink.events)
	}
	if sink.events[0].Actor != "admin2" {
		t.Fatalf("audit actor = %q, want admin2", sink.events[0].Actor)
	}
	revoked, _ := h.Cache.IsRevoked(&auth.Claims{Jti: "del-me"})
	if revoked {
		t.Fatal("cache should no longer report the entry as revoked")
	}
}

func TestDenylistAdmin_Delete_InvalidKind(t *testing.T) {
	h, _, _ := newTestDenylistAdmin(t)
	r := chi.NewRouter()
	r.Delete("/api/v1/admin/denylist/{kind}/{value}", h.Delete)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/denylist/bogus/x", nil)
	rw := httptest.NewRecorder()
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rw.Code)
	}
}

func TestDenylistAdmin_List_StoreError(t *testing.T) {
	h, _, _ := newTestDenylistAdmin(t)
	h.Store = &erroringDenylistStore{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/denylist", nil)
	rw := httptest.NewRecorder()
	h.List(rw, req)
	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", rw.Code)
	}
}

type erroringDenylistStore struct{}

var errDenylistBoom = errors.New("boom")

func (erroringDenylistStore) List(ctx context.Context) ([]denylist.Entry, error) {
	return nil, errDenylistBoom
}
func (erroringDenylistStore) Add(ctx context.Context, e denylist.Entry) error {
	return errDenylistBoom
}
func (erroringDenylistStore) Remove(ctx context.Context, kind, value string) error {
	return errDenylistBoom
}
