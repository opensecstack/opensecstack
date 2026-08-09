package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
	"github.com/opensecstack/opensecstack/irflow/internal/playbook"
)

// bodyOf is a tiny helper for building request bodies inline.
func bodyOf(s string) *bytes.Buffer { return bytes.NewBufferString(s) }

// ---------------------------------------------------------------------------
// errStore wraps apiMockStore and lets tests force a specific method to
// return an error, so handler 500-branches (which the happy-path mock store
// can never reach on its own) are actually exercised.
// ---------------------------------------------------------------------------

type errStore struct {
	*apiMockStore
	failList             error
	failPatch            error
	failDelete           error
	failStats            error
	failGetTimeline      error
	failListIOCs         error
	failAddIOC           error
	failListPending      error
	failAddTimelineEntry error
}

func newErrStore() *errStore {
	return &errStore{apiMockStore: newAPIMockStore()}
}

func (e *errStore) List(ctx context.Context, opts incident.ListOptions) ([]incident.Incident, int, error) {
	if e.failList != nil {
		return nil, 0, e.failList
	}
	return e.apiMockStore.List(ctx, opts)
}

func (e *errStore) Update(ctx context.Context, inc *incident.Incident) error {
	if e.failPatch != nil {
		return e.failPatch
	}
	return e.apiMockStore.Update(ctx, inc)
}

func (e *errStore) Delete(ctx context.Context, id string) error {
	if e.failDelete != nil {
		return e.failDelete
	}
	return e.apiMockStore.Delete(ctx, id)
}

func (e *errStore) Stats(ctx context.Context) (*incident.Stats, error) {
	if e.failStats != nil {
		return nil, e.failStats
	}
	return e.apiMockStore.Stats(ctx)
}

func (e *errStore) GetTimeline(ctx context.Context, incidentID string) ([]incident.TimelineEntry, error) {
	if e.failGetTimeline != nil {
		return nil, e.failGetTimeline
	}
	return e.apiMockStore.GetTimeline(ctx, incidentID)
}

func (e *errStore) ListIOCs(ctx context.Context, incidentID string) ([]incident.IOCEnrichment, error) {
	if e.failListIOCs != nil {
		return nil, e.failListIOCs
	}
	return e.apiMockStore.ListIOCs(ctx, incidentID)
}

func (e *errStore) AddIOC(ctx context.Context, ioc *incident.IOCEnrichment) error {
	if e.failAddIOC != nil {
		return e.failAddIOC
	}
	return e.apiMockStore.AddIOC(ctx, ioc)
}

func (e *errStore) ListPendingActions(ctx context.Context, incidentID string) ([]incident.PendingAction, error) {
	if e.failListPending != nil {
		return nil, e.failListPending
	}
	return e.apiMockStore.ListPendingActions(ctx, incidentID)
}

func (e *errStore) AddTimelineEntry(ctx context.Context, entry *incident.TimelineEntry) error {
	if e.failAddTimelineEntry != nil {
		return e.failAddTimelineEntry
	}
	return e.apiMockStore.AddTimelineEntry(ctx, entry)
}

func newTestServerWithErrStore(store *errStore) *Server {
	svc := incident.NewService(store)
	return NewServer(Options{Logger: zap.NewNop(), Incidents: svc})
}

// ---------------------------------------------------------------------------
// 500-branch coverage: incidents.go
// ---------------------------------------------------------------------------

func TestListIncidents_500OnStoreError(t *testing.T) {
	store := newErrStore()
	store.failList = errors.New("db unavailable")
	srv := newTestServerWithErrStore(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestPatchIncident_500OnStoreError(t *testing.T) {
	store := newErrStore()
	seedIncident(store.apiMockStore, "inc-1", "X", incident.SeverityP2)
	store.failPatch = errors.New("write failed")
	srv := newTestServerWithErrStore(store)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/incidents/inc-1", bodyOf(`{"title":"new"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

func TestDeleteIncident_500OnStoreError(t *testing.T) {
	store := newErrStore()
	seedIncident(store.apiMockStore, "inc-1", "X", incident.SeverityP2)
	store.failDelete = errors.New("write failed")
	srv := newTestServerWithErrStore(store)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/incidents/inc-1", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// TestDeleteIncident_404WhenMissing guards against a real bug found while
// writing these tests: handleDeleteIncident previously mapped incident.ErrNotFound
// (returned by the store when the ID doesn't exist) to 500 Internal Server
// Error instead of 404 Not Found, which would misleadingly page on-call for
// what is actually a client error (deleting something already gone).
func TestDeleteIncident_404WhenMissing(t *testing.T) {
	srv, _ := newTestServer()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/incidents/does-not-exist", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestPatchIncident_404WhenMissing is the PATCH analogue of the bug above:
// handlePatchIncident previously mapped incident.ErrNotFound to 500 too.
func TestPatchIncident_404WhenMissing(t *testing.T) {
	srv, _ := newTestServer()

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/incidents/does-not-exist", bodyOf(`{"title":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestPatchIncident_400OnInvalidTransition documents/fixes the second half
// of the same bug class: an invalid status transition (e.g. open -> closed
// skipping containment) previously surfaced as 500 Internal Server Error
// instead of 400 Bad Request.
func TestPatchIncident_400OnInvalidTransition(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "inc-1", "X", incident.SeverityP2) // seeded status = StatusOpen

	// StatusOpen -> StatusContained skips the required "investigating" step
	// and is not a valid direct transition.
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/incidents/inc-1", bodyOf(`{"status":"contained"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestStats_500OnStoreError(t *testing.T) {
	store := newErrStore()
	store.failStats = errors.New("aggregation failed")
	srv := newTestServerWithErrStore(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var body map[string]string
	decodeJSON(t, rec, &body)
	if body["error"] != "stats unavailable" {
		t.Errorf("error = %q, want %q", body["error"], "stats unavailable")
	}
}

func TestGetTimeline_500OnStoreError(t *testing.T) {
	store := newErrStore()
	seedIncident(store.apiMockStore, "inc-1", "X", incident.SeverityP2)
	store.failGetTimeline = errors.New("read failed")
	srv := newTestServerWithErrStore(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc-1/timeline", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestListActions_500OnStoreError(t *testing.T) {
	// handleListActions reuses GetTimeline internally.
	store := newErrStore()
	seedIncident(store.apiMockStore, "inc-1", "X", incident.SeverityP2)
	store.failGetTimeline = errors.New("read failed")
	srv := newTestServerWithErrStore(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc-1/actions", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestListIOCs_500OnStoreError(t *testing.T) {
	store := newErrStore()
	seedIncident(store.apiMockStore, "inc-1", "X", incident.SeverityP2)
	store.failListIOCs = errors.New("read failed")
	srv := newTestServerWithErrStore(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc-1/iocs", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestAddIOC_500OnStoreError(t *testing.T) {
	store := newErrStore()
	seedIncident(store.apiMockStore, "inc-1", "X", incident.SeverityP2)
	store.failAddIOC = errors.New("write failed")
	srv := newTestServerWithErrStore(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/inc-1/iocs", bodyOf(`{"ioc_type":"ip","ioc_value":"1.2.3.4"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestListPendingActions_500OnStoreError(t *testing.T) {
	store := newErrStore()
	seedIncident(store.apiMockStore, "inc-1", "X", incident.SeverityP2)
	store.failListPending = errors.New("read failed")
	srv := newTestServerWithErrStore(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc-1/actions/pending", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// ---------------------------------------------------------------------------
// 500-branch coverage: webhooks.go
// ---------------------------------------------------------------------------

func TestCyberPathWebhook_500OnAddTimelineEntryError(t *testing.T) {
	store := newErrStore()
	seedIncident(store.apiMockStore, "inc-cp", "X", incident.SeverityP2)
	store.failAddTimelineEntry = errors.New("write failed")
	svc := incident.NewService(store)
	srv := NewServer(Options{
		Logger:    zap.NewNop(),
		Incidents: svc,
		Webhooks:  WebhookSecrets{CyberPath: webhookTestSecret},
	})

	payload := []byte(`{"event_id":"evt-1","event_type":"cyberpath.incident_remediation_completed","incident_id":"inc-cp","cohort_id":"c1"}`)
	req := signedRequest(t, http.MethodPost, "/api/v1/webhooks/cyberpath/remediation", payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 500-branch coverage: playbooks.go (uses apiMockPlaybookStore's own error
// injection, defined below).
// ---------------------------------------------------------------------------

type errPlaybookStore struct {
	*apiMockPlaybookStore
	failList   error
	failCreate error
}

func (e *errPlaybookStore) List(ctx context.Context, opts playbook.ListOptions) ([]playbook.Playbook, int, error) {
	if e.failList != nil {
		return nil, 0, e.failList
	}
	return e.apiMockPlaybookStore.List(ctx, opts)
}

func (e *errPlaybookStore) Create(ctx context.Context, pb *playbook.Playbook) error {
	if e.failCreate != nil {
		return e.failCreate
	}
	return e.apiMockPlaybookStore.Create(ctx, pb)
}

func TestListPlaybooks_500OnStoreError(t *testing.T) {
	pbStore := &errPlaybookStore{apiMockPlaybookStore: newAPIMockPlaybookStore(), failList: errors.New("db down")}
	logger := zap.NewNop()
	executor := playbook.NewExecutor(logger)
	svc := playbook.NewService(pbStore, executor, logger)
	srv := NewServer(Options{Logger: logger, Playbooks: svc})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/playbooks", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestListPlaybooks_200_FiltersByStatusAndPaginates(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()
	seedPlaybook(store, "pb-1", "Active one", playbook.PlaybookStatusActive)
	seedPlaybook(store, "pb-2", "Draft one", playbook.PlaybookStatusDraft)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/playbooks?status=active", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body playbookListResponse
	decodeJSON(t, rec, &body)
	if body.TotalCount != 1 {
		t.Fatalf("total_count = %d, want 1 (status filter)", body.TotalCount)
	}
	if len(body.Data) != 1 || body.Data[0].ID != "pb-1" {
		t.Errorf("data = %+v, want only pb-1", body.Data)
	}
}

func TestCreatePlaybook_201(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()

	payload := `{"name":"New PB","description":"desc","version":"2.0"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/playbooks", bodyOf(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var pb playbook.Playbook
	decodeJSON(t, rec, &pb)
	if pb.Name != "New PB" {
		t.Errorf("name = %q, want %q", pb.Name, "New PB")
	}
	if pb.ID == "" {
		t.Error("expected non-empty generated ID")
	}
	if _, ok := store.playbooks[pb.ID]; !ok {
		t.Error("playbook was not persisted to the store")
	}
}

func TestCreatePlaybook_400OnInvalidJSON(t *testing.T) {
	srv, _ := newTestServerWithPlaybooks()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/playbooks", bodyOf("not json"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreatePlaybook_400OnMissingName(t *testing.T) {
	// playbook.Service.Create returns ErrInvalid when Name == "" — the
	// handler must map that to 400, not 500.
	srv, _ := newTestServerWithPlaybooks()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/playbooks", bodyOf(`{"description":"no name"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreatePlaybook_500OnStoreError(t *testing.T) {
	pbStore := &errPlaybookStore{apiMockPlaybookStore: newAPIMockPlaybookStore(), failCreate: errors.New("db down")}
	logger := zap.NewNop()
	executor := playbook.NewExecutor(logger)
	svc := playbook.NewService(pbStore, executor, logger)
	srv := NewServer(Options{Logger: logger, Playbooks: svc})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/playbooks", bodyOf(`{"name":"X"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}
