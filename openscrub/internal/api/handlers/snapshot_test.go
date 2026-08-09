package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/api/handlers"
	"github.com/opensecstack/openscrub/internal/dataplane"
)

type fakeRulesSource struct {
	bl, rl, sc     int
	v4, v6         int
	countErr, splitErr error
}

func (f *fakeRulesSource) CountByType(context.Context) (int, int, int, error) {
	return f.bl, f.rl, f.sc, f.countErr
}
func (f *fakeRulesSource) V4V6Split(context.Context) (int, int, error) {
	return f.v4, f.v6, f.splitErr
}

type fakeIOCSource struct {
	last  time.Time
	count int
	err   error
}

func (f *fakeIOCSource) LastIngest(context.Context) (time.Time, int, error) {
	return f.last, f.count, f.err
}

type fakeCitadelSource struct{ depth int }

func (f *fakeCitadelSource) QueueDepth() int { return f.depth }

func TestSnapshotGetAllSourcesNil(t *testing.T) {
	h := &handlers.Snapshot{Logger: zerolog.Nop()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/snapshot", nil)
	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	var resp handlers.SnapshotResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RulesActive != 0 || resp.PPSPassed != 0 || resp.DataplaneAttached {
		t.Fatalf("expected all-zero snapshot with nil sources, got %+v", resp)
	}
	if resp.SnapshotAt.IsZero() {
		t.Fatal("expected SnapshotAt to be populated")
	}
}

func TestSnapshotGetAggregatesAllSources(t *testing.T) {
	plane := dataplane.NewNoopClient()
	plane.SetStats(dataplane.Stats{PacketsPassed: 100, PacketsDropped: 5, PacketsRatelimited: 2, SynCookiesSent: 7})

	fixedNow := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	iocTime := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	h := &handlers.Snapshot{
		Plane:             plane,
		Rules:             &fakeRulesSource{bl: 3, rl: 2, sc: 1, v4: 3, v6: 0},
		IOC:               &fakeIOCSource{last: iocTime, count: 42},
		Citadel:           &fakeCitadelSource{depth: 9},
		DataplaneAttached: func() bool { return true },
		Logger:            zerolog.Nop(),
		Now:               func() time.Time { return fixedNow },
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/snapshot", nil)
	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp handlers.SnapshotResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.PPSPassed != 100 || resp.PPSDropped != 5 || resp.PPSRatelimited != 2 || resp.SynCookiesSent != 7 {
		t.Fatalf("dataplane stats not reflected: %+v", resp)
	}
	// RulesActive = bl + rl + sc = 3+2+1 = 6.
	if resp.RulesActive != 6 || resp.RulesRatelimit != 2 || resp.RulesSynCookie != 1 {
		t.Fatalf("rule counts not reflected: %+v", resp)
	}
	if resp.RulesV4 != 3 || resp.RulesV6 != 0 {
		t.Fatalf("v4/v6 split not reflected: %+v", resp)
	}
	if !resp.IOCPullLastAt.Equal(iocTime) || resp.IOCPullCount != 42 {
		t.Fatalf("ioc fields not reflected: %+v", resp)
	}
	if resp.CitadelQueueDepth != 9 {
		t.Fatalf("citadel queue depth = %d, want 9", resp.CitadelQueueDepth)
	}
	if !resp.DataplaneAttached {
		t.Fatal("expected DataplaneAttached = true")
	}
	if !resp.SnapshotAt.Equal(fixedNow) {
		t.Fatalf("SnapshotAt = %v, want injected %v (Now hook not honored)", resp.SnapshotAt, fixedNow)
	}
}

func TestSnapshotGetToleratesSourceErrors(t *testing.T) {
	h := &handlers.Snapshot{
		Rules:   &fakeRulesSource{countErr: errors.New("boom"), splitErr: errors.New("boom")},
		IOC:     &fakeIOCSource{err: errors.New("boom")},
		Citadel: &fakeCitadelSource{depth: 0},
		Logger:  zerolog.Nop(),
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/snapshot", nil)
	h.Get(rec, req)

	// Best-effort: downstream errors must never turn into a 500.
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 even with failing sources", rec.Code)
	}
	var resp handlers.SnapshotResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RulesActive != 0 || resp.RulesV4 != 0 || resp.IOCPullCount != 0 {
		t.Fatalf("expected zeroed fields on source error, got %+v", resp)
	}
}
