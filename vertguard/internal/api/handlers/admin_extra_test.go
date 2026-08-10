package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/auth/denylist"
	"github.com/opensecstack/vertguard/internal/threatfeed/atlas"
)

// ─── admin_atlas.go — callerIdentity / recordSync remaining branches ──

func TestAdminAtlas_Sync_Success_WithAuthenticatedClaims(t *testing.T) {
	syncer := &fakeSyncer{rep: atlas.Report{Added: 1}}
	sink := &captureSink{}
	logger := zerolog.Nop()
	h := NewAdminAtlasHandler(syncer, sink, &logger, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/atlas/sync", nil)
	ctx := auth.InjectClaimsForTest(req.Context(), &auth.Claims{Sub: "op7", Role: auth.RoleAdmin})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.Sync(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.events))
	}
	if sink.events[0].Actor != "op7" || sink.events[0].Role != auth.RoleAdmin {
		t.Errorf("audit actor/role = %q/%q, want op7/%s", sink.events[0].Actor, sink.events[0].Role, auth.RoleAdmin)
	}
}

func TestAdminAtlas_Sync_Success_NilSink_NoPanic(t *testing.T) {
	syncer := &fakeSyncer{rep: atlas.Report{Added: 1}}
	logger := zerolog.Nop()
	h := NewAdminAtlasHandler(syncer, nil, &logger, nil) // Sink deliberately nil
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/atlas/sync", nil)
	rec := httptest.NewRecorder()
	h.Sync(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

// ─── denylist_admin.go — refreshCache failure branch ───────────────

func TestDenylistAdmin_Create_CacheRefreshFails_StillReturns201(t *testing.T) {
	// The write to the underlying store must already have succeeded by
	// the time refreshCache runs, so a cache refresh failure is logged
	// but non-fatal — the response is still 201 and the entry persists.
	workingStore := denylist.NewMemoryStore()
	brokenCache := denylist.NewCache(erroringDenylistCacheStore{})
	sink := &recordingSink{}
	logger := zerolog.Nop()
	h := NewDenylistAdminHandler(workingStore, brokenCache, sink, &logger)

	body := `{"kind":"jti","value":"tok-999","reason":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/denylist", bytes.NewBufferString(body))
	rw := httptest.NewRecorder()
	h.Create(rw, req)

	if rw.Code != http.StatusCreated {
		t.Fatalf("status=%d, want 201; body=%s", rw.Code, rw.Body.String())
	}
	list, _ := workingStore.List(context.Background())
	if len(list) != 1 || list[0].Value != "tok-999" {
		t.Fatalf("entry not persisted despite cache-refresh failure: %+v", list)
	}
	if len(sink.events) != 1 || sink.events[0].Action != "REVOKE_TOKEN" {
		t.Fatalf("audit event missing despite cache-refresh failure: %+v", sink.events)
	}
}

// erroringDenylistCacheStore always fails List, which Cache.Refresh
// depends on.
type erroringDenylistCacheStore struct{}

func (erroringDenylistCacheStore) List(context.Context) ([]denylist.Entry, error) {
	return nil, errDenylistBoom
}
func (erroringDenylistCacheStore) Add(context.Context, denylist.Entry) error { return nil }
func (erroringDenylistCacheStore) Remove(context.Context, string, string) error {
	return nil
}

func TestDenylistAdmin_Create_NilCache_SkipsRefresh(t *testing.T) {
	store := denylist.NewMemoryStore()
	sink := &recordingSink{}
	logger := zerolog.Nop()
	h := NewDenylistAdminHandler(store, nil, sink, &logger) // Cache deliberately nil
	body := `{"kind":"sub","value":"user-nocache"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/denylist", bytes.NewBufferString(body))
	rw := httptest.NewRecorder()
	h.Create(rw, req)
	if rw.Code != http.StatusCreated {
		t.Fatalf("status=%d, want 201; body=%s", rw.Code, rw.Body.String())
	}
}
