package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
)

// ---------------------------------------------------------------------------
// In-memory mock store (mirrors the one in incident/service_test.go but lives
// in package api so we can construct a Server without import cycles).
// ---------------------------------------------------------------------------

type apiMockStore struct {
	incidents map[string]*incident.Incident
	actions   map[string][]incident.IncidentAction
	iocs      map[string][]incident.IOCEnrichment
	timeline  map[string][]incident.TimelineEntry
}

func newAPIMockStore() *apiMockStore {
	return &apiMockStore{
		incidents: make(map[string]*incident.Incident),
		actions:   make(map[string][]incident.IncidentAction),
		iocs:      make(map[string][]incident.IOCEnrichment),
		timeline:  make(map[string][]incident.TimelineEntry),
	}
}

func (m *apiMockStore) Create(_ context.Context, inc *incident.Incident) error {
	if inc.ID == "" {
		return errors.New("incident ID must be set")
	}
	cp := *inc
	m.incidents[inc.ID] = &cp
	return nil
}

func (m *apiMockStore) Get(_ context.Context, id string) (*incident.Incident, error) {
	inc, ok := m.incidents[id]
	if !ok {
		return nil, incident.ErrNotFound
	}
	cp := *inc
	return &cp, nil
}

func (m *apiMockStore) List(_ context.Context, opts incident.ListOptions) ([]incident.Incident, int, error) {
	var all []incident.Incident
	for _, inc := range m.incidents {
		if opts.Status != "" && string(inc.Status) != opts.Status {
			continue
		}
		if opts.Severity != "" && string(inc.Severity) != opts.Severity {
			continue
		}
		if opts.Source != "" && string(inc.Source) != opts.Source {
			continue
		}
		all = append(all, *inc)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})
	total := len(all)
	offset := (opts.Page - 1) * opts.PerPage
	if offset < 0 {
		offset = 0
	}
	if offset >= len(all) {
		return []incident.Incident{}, total, nil
	}
	end := offset + opts.PerPage
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], total, nil
}

func (m *apiMockStore) Update(_ context.Context, inc *incident.Incident) error {
	if _, ok := m.incidents[inc.ID]; !ok {
		return incident.ErrNotFound
	}
	cp := *inc
	m.incidents[inc.ID] = &cp
	return nil
}

func (m *apiMockStore) Delete(_ context.Context, id string) error {
	if _, ok := m.incidents[id]; !ok {
		return incident.ErrNotFound
	}
	delete(m.incidents, id)
	return nil
}

func (m *apiMockStore) AddAction(_ context.Context, action *incident.IncidentAction) error {
	cp := *action
	m.actions[action.IncidentID] = append(m.actions[action.IncidentID], cp)
	return nil
}

func (m *apiMockStore) ListActions(_ context.Context, incidentID string) ([]incident.IncidentAction, error) {
	return m.actions[incidentID], nil
}

func (m *apiMockStore) AddIOC(_ context.Context, ioc *incident.IOCEnrichment) error {
	cp := *ioc
	m.iocs[ioc.IncidentID] = append(m.iocs[ioc.IncidentID], cp)
	return nil
}

func (m *apiMockStore) ListIOCs(_ context.Context, incidentID string) ([]incident.IOCEnrichment, error) {
	return m.iocs[incidentID], nil
}

func (m *apiMockStore) GetTimeline(_ context.Context, incidentID string) ([]incident.TimelineEntry, error) {
	return m.timeline[incidentID], nil
}

func (m *apiMockStore) Stats(_ context.Context) (*incident.Stats, error) {
	stats := &incident.Stats{
		BySeverity: map[string]int{},
		ByStatus:   map[string]int{},
		BySource:   map[string]int{},
	}
	for _, inc := range m.incidents {
		stats.Total++
		stats.BySeverity[string(inc.Severity)]++
		stats.ByStatus[string(inc.Status)]++
		stats.BySource[string(inc.Source)]++
	}
	return stats, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestServer() (*Server, *apiMockStore) {
	store := newAPIMockStore()
	svc := incident.NewService(store)
	logger, _ := zap.NewDevelopment()
	srv := NewServer(Options{Logger: logger, Incidents: svc})
	return srv, store
}

// seedIncident creates an incident directly in the mock store and returns it.
func seedIncident(store *apiMockStore, id, title string, sev incident.Severity) *incident.Incident {
	now := time.Now().UTC()
	inc := &incident.Incident{
		ID:        id,
		Title:     title,
		Severity:  sev,
		Status:    incident.StatusOpen,
		Source:    incident.SourceManual,
		CreatedAt: now,
		UpdatedAt: now,
	}
	store.incidents[id] = inc
	return inc
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Health endpoint tests
// ---------------------------------------------------------------------------

func TestHealth_ReturnsOK(t *testing.T) {
	srv, _ := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	decodeJSON(t, rec, &body)
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}

func TestHealthDetail_ReturnsVersion(t *testing.T) {
	srv, _ := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/health/detail", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]interface{}
	decodeJSON(t, rec, &body)
	if body["version"] == nil || body["version"] == "" {
		t.Error("expected non-empty version field")
	}
}

// ---------------------------------------------------------------------------
// Incident CRUD tests
// ---------------------------------------------------------------------------

func TestCreateIncident_201(t *testing.T) {
	srv, _ := newTestServer()

	payload := `{"title":"Server compromise","severity":"P1","source":"apiguard"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var inc incident.Incident
	decodeJSON(t, rec, &inc)
	if inc.ID == "" {
		t.Error("expected non-empty incident ID")
	}
	if inc.Status != incident.StatusOpen {
		t.Errorf("Status = %q, want %q", inc.Status, incident.StatusOpen)
	}
}

func TestCreateIncident_400_MissingTitle(t *testing.T) {
	srv, _ := newTestServer()

	payload := `{"severity":"P1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var body map[string]string
	decodeJSON(t, rec, &body)
	if body["error"] == "" {
		t.Error("expected error message in response")
	}
}

func TestCreateIncident_400_InvalidJSON(t *testing.T) {
	srv, _ := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateIncident_400_MissingSeverity(t *testing.T) {
	srv, _ := newTestServer()

	payload := `{"title":"No severity"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestGetIncident_200(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "test-id-1", "Test incident", incident.SeverityP2)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/test-id-1", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var inc incident.Incident
	decodeJSON(t, rec, &inc)
	if inc.ID != "test-id-1" {
		t.Errorf("ID = %q, want %q", inc.ID, "test-id-1")
	}
}

func TestGetIncident_404(t *testing.T) {
	srv, _ := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/nonexistent", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestListIncidents_200_Empty(t *testing.T) {
	srv, _ := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body listResponse
	decodeJSON(t, rec, &body)
	if body.TotalCount != 0 {
		t.Errorf("total_count = %d, want 0", body.TotalCount)
	}
	if len(body.Data) != 0 {
		t.Errorf("len(data) = %d, want 0", len(body.Data))
	}
}

func TestListIncidents_200_WithData(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "id-1", "First", incident.SeverityP1)
	seedIncident(store, "id-2", "Second", incident.SeverityP2)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?page=1&per_page=10", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body listResponse
	decodeJSON(t, rec, &body)
	if body.TotalCount != 2 {
		t.Errorf("total_count = %d, want 2", body.TotalCount)
	}
}

func TestPatchIncident_200(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "patch-id", "Original", incident.SeverityP2)

	payload := `{"title":"Updated title"}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/incidents/patch-id", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var inc incident.Incident
	decodeJSON(t, rec, &inc)
	if inc.Title != "Updated title" {
		t.Errorf("Title = %q, want %q", inc.Title, "Updated title")
	}
}

func TestDeleteIncident_204(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "delete-id", "Delete me", incident.SeverityP4)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/incidents/delete-id", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// Confirm it's gone.
	if _, ok := store.incidents["delete-id"]; ok {
		t.Error("expected incident to be deleted from store")
	}
}

func TestSubmitAction_201(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "action-id", "Action incident", incident.SeverityP1)

	payload := `{
		"action_type": "contain",
		"operator_id": "user-alice",
		"verifier_id": "user-bob",
		"description": "Isolated the host"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/action-id/actions", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var action incident.IncidentAction
	decodeJSON(t, rec, &action)
	if action.IncidentID != "action-id" {
		t.Errorf("IncidentID = %q, want %q", action.IncidentID, "action-id")
	}
}

func TestSubmitAction_400_SoD(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "sod-id", "SoD incident", incident.SeverityP1)

	// operator_id == verifier_id should be rejected by the handler.
	payload := `{
		"action_type": "contain",
		"operator_id": "user-alice",
		"verifier_id": "user-alice",
		"description": "Self-verified"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/sod-id/actions", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (SoD violation)", rec.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// Stub endpoint tests
// ---------------------------------------------------------------------------

// When the Server is constructed without a playbook service (e.g. the
// incident-only unit tests), playbook routes should return 503 rather than
// 500 or route-not-found errors.
func TestPlaybooks_503_WhenServiceNil(t *testing.T) {
	srv, _ := newTestServer()

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/playbooks"},
		{http.MethodPost, "/api/v1/playbooks"},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: status = %d, want %d", ep.method, ep.path, rec.Code, http.StatusServiceUnavailable)
		}
	}
}

// When no webhook secret is configured, every source must return 503 so a
// misconfigured IRFlow cannot accept unauthenticated events.
func TestWebhooks_503_WhenSecretNotConfigured(t *testing.T) {
	srv, _ := newTestServer()

	endpoints := []string{
		"/api/v1/webhooks/apiguard",
		"/api/v1/webhooks/citadel",
		"/api/v1/webhooks/threatflow",
	}

	for _, path := range endpoints {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString("{}"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("POST %s: status = %d, want %d", path, rec.Code, http.StatusServiceUnavailable)
		}
	}
}

func TestStats_200(t *testing.T) {
	srv, _ := newTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]interface{}
	decodeJSON(t, rec, &body)
	if body["total"] == nil {
		t.Error("expected 'total' field in stats response")
	}
	if body["by_severity"] == nil {
		t.Error("expected 'by_severity' field in stats response")
	}
	if body["by_status"] == nil {
		t.Error("expected 'by_status' field in stats response")
	}
}

// ---------------------------------------------------------------------------
// IOC endpoint tests
// ---------------------------------------------------------------------------

func TestAddIOC_201(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "ioc-inc", "IOC incident", incident.SeverityP2)

	payload := `{
		"ioc_type": "ip",
		"ioc_value": "192.168.1.100",
		"confidence": 0.95,
		"source": "threatflow"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/ioc-inc/iocs", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

func TestListIOCs_200(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "ioc-list", "IOC list test", incident.SeverityP2)
	store.iocs["ioc-list"] = []incident.IOCEnrichment{
		{ID: "ioc-1", IncidentID: "ioc-list", IOCType: "ip", IOCValue: "10.0.0.1"},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/ioc-list/iocs", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var iocs []incident.IOCEnrichment
	decodeJSON(t, rec, &iocs)
	if len(iocs) != 1 {
		t.Errorf("len(iocs) = %d, want 1", len(iocs))
	}
}

func TestGetTimeline_200(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "tl-inc", "Timeline test", incident.SeverityP1)
	store.timeline["tl-inc"] = []incident.TimelineEntry{
		{ID: "tl-1", IncidentID: "tl-inc", EntryType: "status_change", Summary: "Opened"},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/tl-inc/timeline", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var entries []incident.TimelineEntry
	decodeJSON(t, rec, &entries)
	if len(entries) != 1 {
		t.Errorf("len(entries) = %d, want 1", len(entries))
	}
}
