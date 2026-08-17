package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/vertguard/internal/audit"
)

// fakeAuditLister implements AuditLister for handler tests.
type fakeAuditLister struct {
	events   []audit.Event
	err      error
	gotLimit int
	gotSince string
}

func (f *fakeAuditLister) ListAuditEvents(_ context.Context, limit int, sinceID string) ([]audit.Event, error) {
	f.gotLimit = limit
	f.gotSince = sinceID
	if f.err != nil {
		return nil, f.err
	}
	return f.events, nil
}

func TestNewAuditHandler(t *testing.T) {
	fl := &fakeAuditLister{}
	h := NewAuditHandler(fl)
	if h == nil || h.Store != fl {
		t.Fatalf("NewAuditHandler did not wire the store: %+v", h)
	}
}

func TestAuditHandler_List_NilHandlerReturns503(t *testing.T) {
	var h *AuditHandler
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
}

func TestAuditHandler_List_NilStoreReturns503(t *testing.T) {
	h := &AuditHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
}

func TestAuditHandler_List_Success(t *testing.T) {
	fl := &fakeAuditLister{events: []audit.Event{{Actor: "alice"}, {Actor: "bob"}}}
	h := NewAuditHandler(fl)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit?limit=50&since=abc", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fl.gotLimit != 50 || fl.gotSince != "abc" {
		t.Fatalf("store called with limit=%d since=%q, want 50/abc", fl.gotLimit, fl.gotSince)
	}
	var resp struct {
		Events []audit.Event `json:"events"`
		Count  int           `json:"count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 2 || len(resp.Events) != 2 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestAuditHandler_List_DefaultLimit(t *testing.T) {
	fl := &fakeAuditLister{}
	h := NewAuditHandler(fl)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)
	if fl.gotLimit != 100 {
		t.Fatalf("default limit = %d, want 100", fl.gotLimit)
	}
}

func TestAuditHandler_List_StoreError(t *testing.T) {
	fl := &fakeAuditLister{err: errors.New("db down")}
	h := NewAuditHandler(fl)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", rr.Code)
	}
}

func TestParseIntQuery(t *testing.T) {
	cases := []struct {
		name string
		url  string
		key  string
		def  int
		want int
	}{
		{"missing uses default", "/x", "limit", 100, 100},
		{"valid value", "/x?limit=25", "limit", 100, 25},
		{"zero uses default", "/x?limit=0", "limit", 100, 100},
		{"non-numeric uses default", "/x?limit=abc", "limit", 100, 100},
		{"negative (has minus sign) uses default", "/x?limit=-5", "limit", 100, 100},
		{"exceeds cap uses default", "/x?limit=99999999", "limit", 100, 100},
		{"exactly at cap boundary accepted", "/x?limit=1000000", "limit", 100, 1000000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, c.url, nil)
			got := parseIntQuery(req, c.key, c.def)
			if got != c.want {
				t.Errorf("parseIntQuery(%q) = %d, want %d", c.url, got, c.want)
			}
		})
	}
}
