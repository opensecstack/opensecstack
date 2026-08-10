package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/vertguard/internal/ioc"
)

// fakeIOCStore is an in-memory IOCStore fake — lets threatfeed handler
// tests exercise the Store-backed branches without a Postgres pool.
type fakeIOCStore struct {
	listErr    error
	upsertErr  error
	rows       []ioc.IOC
	total      int
	nextCursor int
	upserted   []ioc.IOC
	upsertRes  ioc.UpsertResult
}

func (f *fakeIOCStore) List(_ context.Context, _ ioc.ListFilter) ([]ioc.IOC, int, error) {
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.rows, f.nextCursor, nil
}

func (f *fakeIOCStore) Upsert(_ context.Context, in ioc.IOC) (ioc.UpsertResult, error) {
	if f.upsertErr != nil {
		return 0, f.upsertErr
	}
	f.upserted = append(f.upserted, in)
	return f.upsertRes, nil
}

// ─── CreateIOC ──────────────────────────────────────────────────────

func TestCreateIOC_NilStore_Returns503(t *testing.T) {
	h := &ThreatFeedHandler{}
	body, _ := json.Marshal(map[string]any{"kind": "ip", "value": "1.2.3.4"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/ioc", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.CreateIOC(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503; body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateIOC_MalformedJSON_Returns400(t *testing.T) {
	h := &ThreatFeedHandler{Store: &fakeIOCStore{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/ioc", bytes.NewReader([]byte("{bad")))
	rr := httptest.NewRecorder()
	h.CreateIOC(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}

func TestCreateIOC_UnknownField_Rejected(t *testing.T) {
	// DisallowUnknownFields is load-bearing — a typo'd field must not
	// be silently dropped.
	h := &ThreatFeedHandler{Store: &fakeIOCStore{}}
	body, _ := json.Marshal(map[string]any{"kind": "ip", "value": "1.2.3.4", "bogus_field": 1})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/ioc", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.CreateIOC(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 for unknown field", rr.Code)
	}
}

func TestCreateIOC_InvalidKind_Returns400(t *testing.T) {
	h := &ThreatFeedHandler{Store: &fakeIOCStore{}}
	body, _ := json.Marshal(map[string]any{"kind": "not_a_kind", "value": "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/ioc", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.CreateIOC(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("invalid_kind")) {
		t.Errorf("body=%s, want invalid_kind code", rr.Body.String())
	}
}

func TestCreateIOC_EmptyValue_Returns400(t *testing.T) {
	h := &ThreatFeedHandler{Store: &fakeIOCStore{}}
	body, _ := json.Marshal(map[string]any{"kind": "ip", "value": "   "})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/ioc", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.CreateIOC(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("invalid_value")) {
		t.Errorf("body=%s, want invalid_value code", rr.Body.String())
	}
}

func TestCreateIOC_ConfidenceOutOfRange_Returns400(t *testing.T) {
	h := &ThreatFeedHandler{Store: &fakeIOCStore{}}
	for _, conf := range []float64{-0.1, 1.1} {
		body, _ := json.Marshal(map[string]any{"kind": "ip", "value": "1.2.3.4", "confidence": conf})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/ioc", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		h.CreateIOC(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("confidence=%v: status=%d, want 400", conf, rr.Code)
		}
	}
}

func TestCreateIOC_BadExpiresAt_Returns400(t *testing.T) {
	h := &ThreatFeedHandler{Store: &fakeIOCStore{}}
	body, _ := json.Marshal(map[string]any{"kind": "ip", "value": "1.2.3.4", "expires_at": "not-a-date"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/ioc", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.CreateIOC(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("invalid_expires_at")) {
		t.Errorf("body=%s, want invalid_expires_at code", rr.Body.String())
	}
}

func TestCreateIOC_StoreError_Returns500(t *testing.T) {
	h := &ThreatFeedHandler{Store: &fakeIOCStore{upsertErr: errors.New("db down")}}
	body, _ := json.Marshal(map[string]any{"kind": "ip", "value": "1.2.3.4"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/ioc", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.CreateIOC(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", rr.Code)
	}
}

func TestCreateIOC_Success_DefaultsSourceAndReportsInserted(t *testing.T) {
	store := &fakeIOCStore{upsertRes: ioc.UpsertInserted}
	wa := &fakeWORM{}
	h := &ThreatFeedHandler{Store: store, Citadel: wa, Tenant: "acme"}
	body, _ := json.Marshal(map[string]any{
		"kind":       "domain",
		"value":      "evil.example.com",
		"confidence": 0.9,
		"expires_at": "2030-01-01T00:00:00Z",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/ioc", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.CreateIOC(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["result"] != "inserted" {
		t.Errorf("result = %q, want inserted", resp["result"])
	}
	if len(store.upserted) != 1 {
		t.Fatalf("expected 1 upsert call, got %d", len(store.upserted))
	}
	row := store.upserted[0]
	if row.Source != "manual" {
		t.Errorf("Source = %q, want default 'manual'", row.Source)
	}
	if row.Tenant != "acme" {
		t.Errorf("Tenant = %q, want acme (from handler)", row.Tenant)
	}
	if row.ExpiresAt == nil {
		t.Fatal("ExpiresAt not set")
	}
	if wa.count.Load() == 0 {
		t.Error("expected CITADEL detection emission on successful insert")
	}
	if wa.last.EventType != "vertguard.threatfeed.ioc_manual_insert" {
		t.Errorf("unexpected event type: %s", wa.last.EventType)
	}
}

func TestCreateIOC_Success_UpdatedResult(t *testing.T) {
	store := &fakeIOCStore{upsertRes: ioc.UpsertUpdated}
	h := &ThreatFeedHandler{Store: store}
	body, _ := json.Marshal(map[string]any{"kind": "ip", "value": "1.2.3.4", "source": "atlas-feed"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/threatfeed/ioc", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.CreateIOC(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["result"] != "updated" {
		t.Errorf("result = %q, want updated", resp["result"])
	}
	if store.upserted[0].Source != "atlas-feed" {
		t.Errorf("Source = %q, want explicit atlas-feed to be respected", store.upserted[0].Source)
	}
}

// ─── ListIOCs / listFromStore ───────────────────────────────────────

func TestListIOCs_StoreBacked_InvalidKind_Returns400(t *testing.T) {
	h := &ThreatFeedHandler{Store: &fakeIOCStore{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/threatfeed/iocs?kind=not_a_kind", nil)
	rr := httptest.NewRecorder()
	h.ListIOCs(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}

func TestListIOCs_StoreBacked_StoreError_Returns500(t *testing.T) {
	h := &ThreatFeedHandler{Store: &fakeIOCStore{listErr: errors.New("boom")}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/threatfeed/iocs", nil)
	rr := httptest.NewRecorder()
	h.ListIOCs(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", rr.Code)
	}
}

func TestListIOCs_StoreBacked_SuccessWithCursorAndEmission(t *testing.T) {
	store := &fakeIOCStore{
		rows: []ioc.IOC{
			{Kind: ioc.KindIP, Value: "1.2.3.4", Source: "manual", Confidence: 0.5},
		},
		nextCursor: 42,
	}
	wa := &fakeWORM{}
	h := &ThreatFeedHandler{Store: store, Citadel: wa}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/threatfeed/iocs?kind=ip&source=manual", nil)
	rr := httptest.NewRecorder()
	h.ListIOCs(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		IOCs       []map[string]any `json:"iocs"`
		Total      int              `json:"total"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.IOCs) != 1 {
		t.Fatalf("iocs = %+v, want 1 row", resp.IOCs)
	}
	if resp.NextCursor != "42" {
		t.Errorf("next_cursor = %q, want 42", resp.NextCursor)
	}
	if wa.count.Load() == 0 {
		t.Error("expected CITADEL emission on non-empty store-backed result")
	}
}

func TestListIOCs_StoreBacked_EmptyResult_NoCursorNoEmission(t *testing.T) {
	store := &fakeIOCStore{rows: nil, nextCursor: 0}
	wa := &fakeWORM{}
	h := &ThreatFeedHandler{Store: store, Citadel: wa}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/threatfeed/iocs", nil)
	rr := httptest.NewRecorder()
	h.ListIOCs(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if _, ok := resp["next_cursor"]; ok {
		t.Errorf("next_cursor should be absent when there is no next page: %+v", resp)
	}
	if wa.count.Load() != 0 {
		t.Error("expected no CITADEL emission on empty result")
	}
}

// ─── CoverageReport ─────────────────────────────────────────────────

func TestCoverageReport_ReturnsTechniqueCount(t *testing.T) {
	h := NewThreatFeedHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/threatfeed/atlas/coverage", nil)
	rr := httptest.NewRecorder()
	h.CoverageReport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	covered, ok := resp["techniques_covered"].(float64)
	if !ok || int(covered) != len(h.atlasSet) {
		t.Errorf("techniques_covered = %v, want %d", resp["techniques_covered"], len(h.atlasSet))
	}
	if resp["atlas_version"] != "embedded-initial" {
		t.Errorf("atlas_version = %v", resp["atlas_version"])
	}
}
