package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/api/handlers"
)

// fakeMitigationLister is a stub handlers.MitigationLister recording the
// arguments it was called with, so tests can assert the handler parses
// and forwards query params correctly.
type fakeMitigationLister struct {
	rows      []handlers.MitigationView
	err       error
	gotSince  time.Time
	gotRuleID uuid.UUID
	gotLimit  int
	called    bool
}

func (f *fakeMitigationLister) List(_ context.Context, since time.Time, ruleID uuid.UUID, limit int) ([]handlers.MitigationView, error) {
	f.called = true
	f.gotSince = since
	f.gotRuleID = ruleID
	f.gotLimit = limit
	return f.rows, f.err
}

func TestMitigationsListNilListerReturnsEmpty(t *testing.T) {
	h := &handlers.Mitigations{Logger: zerolog.Nop()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mitigations", nil)
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	var resp struct {
		Mitigations []handlers.MitigationView `json:"mitigations"`
		Count       int                       `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != 0 || len(resp.Mitigations) != 0 {
		t.Fatalf("expected empty result with nil Lister, got %+v", resp)
	}
}

func TestMitigationsListBadSince(t *testing.T) {
	f := &fakeMitigationLister{}
	h := &handlers.Mitigations{Lister: f, Logger: zerolog.Nop()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mitigations?since=not-a-timestamp", nil)
	h.List(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if f.called {
		t.Fatal("Lister.List should not be called on a bad since param")
	}
}

func TestMitigationsListBadRuleID(t *testing.T) {
	f := &fakeMitigationLister{}
	h := &handlers.Mitigations{Lister: f, Logger: zerolog.Nop()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mitigations?rule_id=not-a-uuid", nil)
	h.List(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if f.called {
		t.Fatal("Lister.List should not be called on a bad rule_id param")
	}
}

func TestMitigationsListForwardsParsedParams(t *testing.T) {
	f := &fakeMitigationLister{rows: []handlers.MitigationView{{ID: uuid.New()}}}
	h := &handlers.Mitigations{Lister: f, Logger: zerolog.Nop()}

	ruleID := uuid.New()
	since := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	url := "/api/v1/mitigations?since=" + since.Format(time.RFC3339) + "&rule_id=" + ruleID.String() + "&limit=50"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if !f.called {
		t.Fatal("expected Lister.List to be called")
	}
	if !f.gotSince.Equal(since) {
		t.Fatalf("since = %v, want %v", f.gotSince, since)
	}
	if f.gotRuleID != ruleID {
		t.Fatalf("rule_id = %v, want %v", f.gotRuleID, ruleID)
	}
	if f.gotLimit != 50 {
		t.Fatalf("limit = %d, want 50", f.gotLimit)
	}

	var resp struct {
		Mitigations []handlers.MitigationView `json:"mitigations"`
		Count       int                       `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Count != 1 || len(resp.Mitigations) != 1 {
		t.Fatalf("expected 1 mitigation in response, got %+v", resp)
	}
}

func TestMitigationsListStoreErrorReturns500(t *testing.T) {
	f := &fakeMitigationLister{err: errors.New("db exploded")}
	h := &handlers.Mitigations{Lister: f, Logger: zerolog.Nop()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mitigations", nil)
	h.List(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500", rec.Code)
	}
}

func TestMitigationsListNilRowsBecomesEmptyArray(t *testing.T) {
	f := &fakeMitigationLister{rows: nil}
	h := &handlers.Mitigations{Lister: f, Logger: zerolog.Nop()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mitigations", nil)
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"mitigations":[]`) {
		t.Fatalf("expected mitigations to serialize as [] not null, got %s", rec.Body.String())
	}
}

func TestMitigationViewFrom(t *testing.T) {
	id, ruleID := uuid.New(), uuid.New()
	started := time.Now()
	v := handlers.MitigationViewFrom(id, ruleID, started, nil, 10, 200, nil, false)
	if v.ID != id || v.RuleID != ruleID || v.PacketsDropped != 10 || v.BytesDropped != 200 {
		t.Fatalf("unexpected view: %+v", v)
	}
	if v.SrcIP != "" {
		t.Fatalf("expected empty SrcIP when src is nil, got %q", v.SrcIP)
	}
}
