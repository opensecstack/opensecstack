package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/threatfeed/atlas"
)

// fakeSyncer drives admin_atlas tests without HTTP.
type fakeSyncer struct {
	rep atlas.Report
	err error
}

func (f *fakeSyncer) Sync(_ context.Context) (atlas.Report, error) {
	return f.rep, f.err
}

// captureSink keeps every audit Event for assertion.
type captureSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureSink) Record(_ context.Context, e audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

type fakeAdminMetrics struct {
	mu    sync.Mutex
	calls []string // formatted as "kind/result"
}

func (f *fakeAdminMetrics) IncAdminSync(kind, result string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, kind+"/"+result)
}

func TestAdminAtlas_Sync_Success(t *testing.T) {
	syncer := &fakeSyncer{rep: atlas.Report{
		Added: 3, Updated: 1, Removed: 0, Unchanged: 50,
		Duration: 250 * time.Millisecond,
	}}
	sink := &captureSink{}
	mx := &fakeAdminMetrics{}
	logger := zerolog.Nop()
	h := NewAdminAtlasHandler(syncer, sink, &logger, mx)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/atlas/sync", nil)
	h.Sync(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["added"].(float64) != 3 || body["updated"].(float64) != 1 {
		t.Fatalf("unexpected counters: %+v", body)
	}
	if _, ok := body["duration_ms"]; !ok {
		t.Fatalf("missing duration_ms")
	}
	if len(sink.events) != 1 || sink.events[0].Action != "ADMIN_ATLAS_SYNC" {
		t.Fatalf("expected one ADMIN_ATLAS_SYNC audit event, got %+v", sink.events)
	}
	if sink.events[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("audit outcome want success, got %s", sink.events[0].Outcome)
	}
	if len(mx.calls) != 1 || mx.calls[0] != "atlas/ok" {
		t.Fatalf("expected one atlas/ok metric, got %+v", mx.calls)
	}
}

func TestAdminAtlas_Sync_Failure(t *testing.T) {
	syncer := &fakeSyncer{err: errors.New("upstream HTTP 503")}
	sink := &captureSink{}
	mx := &fakeAdminMetrics{}
	logger := zerolog.Nop()
	h := NewAdminAtlasHandler(syncer, sink, &logger, mx)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/atlas/sync", nil)
	h.Sync(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "atlas_sync_failed") {
		t.Fatalf("expected error code in body, got %s", rec.Body.String())
	}
	if len(sink.events) != 1 || sink.events[0].Outcome != audit.OutcomeError {
		t.Fatalf("expected one ADMIN_ATLAS_SYNC error event, got %+v", sink.events)
	}
	if len(mx.calls) != 1 || mx.calls[0] != "atlas/fail" {
		t.Fatalf("expected one atlas/fail metric, got %+v", mx.calls)
	}
}

func TestAdminAtlas_Sync_NilSyncer(t *testing.T) {
	logger := zerolog.Nop()
	h := NewAdminAtlasHandler(nil, nil, &logger, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/atlas/sync", nil)
	h.Sync(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 with nil syncer, got %d", rec.Code)
	}
}
