package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
	"github.com/opensecstack/opensecstack/irflow/internal/playbook"
)

// ---------------------------------------------------------------------------
// In-memory mock playbook store (mirrors internal/playbook's own mockStore).
// ---------------------------------------------------------------------------

type apiMockPlaybookStore struct {
	playbooks  map[string]*playbook.Playbook
	executions map[string]*playbook.Execution
}

func newAPIMockPlaybookStore() *apiMockPlaybookStore {
	return &apiMockPlaybookStore{
		playbooks:  make(map[string]*playbook.Playbook),
		executions: make(map[string]*playbook.Execution),
	}
}

func (m *apiMockPlaybookStore) Create(_ context.Context, pb *playbook.Playbook) error {
	cp := *pb
	m.playbooks[pb.ID] = &cp
	return nil
}

func (m *apiMockPlaybookStore) Get(_ context.Context, id string) (*playbook.Playbook, error) {
	pb, ok := m.playbooks[id]
	if !ok {
		return nil, playbook.ErrNotFound
	}
	cp := *pb
	return &cp, nil
}

func (m *apiMockPlaybookStore) List(_ context.Context, opts playbook.ListOptions) ([]playbook.Playbook, int, error) {
	var all []playbook.Playbook
	for _, pb := range m.playbooks {
		if opts.Status != "" && string(pb.Status) != opts.Status {
			continue
		}
		all = append(all, *pb)
	}
	return all, len(all), nil
}

func (m *apiMockPlaybookStore) Update(_ context.Context, pb *playbook.Playbook) error {
	if _, ok := m.playbooks[pb.ID]; !ok {
		return playbook.ErrNotFound
	}
	cp := *pb
	m.playbooks[pb.ID] = &cp
	return nil
}

func (m *apiMockPlaybookStore) Delete(_ context.Context, id string) error {
	if _, ok := m.playbooks[id]; !ok {
		return playbook.ErrNotFound
	}
	delete(m.playbooks, id)
	return nil
}

func (m *apiMockPlaybookStore) CreateExecution(_ context.Context, exec *playbook.Execution) error {
	cp := *exec
	m.executions[exec.ID] = &cp
	return nil
}

func (m *apiMockPlaybookStore) GetExecution(_ context.Context, id string) (*playbook.Execution, error) {
	exec, ok := m.executions[id]
	if !ok {
		return nil, playbook.ErrNotFound
	}
	cp := *exec
	return &cp, nil
}

func (m *apiMockPlaybookStore) ListExecutions(_ context.Context, playbookID string) ([]playbook.Execution, error) {
	var out []playbook.Execution
	for _, e := range m.executions {
		if e.PlaybookID == playbookID {
			out = append(out, *e)
		}
	}
	return out, nil
}

func (m *apiMockPlaybookStore) UpdateExecution(_ context.Context, exec *playbook.Execution) error {
	if _, ok := m.executions[exec.ID]; !ok {
		return playbook.ErrNotFound
	}
	cp := *exec
	m.executions[exec.ID] = &cp
	return nil
}

// newTestServerWithPlaybooks builds a Server wired with both the incident and
// playbook mock stores, in dev-mode auth (no secret configured).
func newTestServerWithPlaybooks() (*Server, *apiMockPlaybookStore) {
	pbStore := newAPIMockPlaybookStore()
	logger, _ := zap.NewDevelopment()
	executor := playbook.NewExecutor(logger)
	svc := playbook.NewService(pbStore, executor, logger)
	srv := NewServer(Options{Logger: logger, Playbooks: svc})
	return srv, pbStore
}

func seedPlaybook(store *apiMockPlaybookStore, id, name string, status playbook.PlaybookStatus) *playbook.Playbook {
	now := time.Now().UTC()
	pb := &playbook.Playbook{
		ID:        id,
		Name:      name,
		Version:   "1.0",
		Status:    status,
		CreatedAt: now,
		UpdatedAt: now,
	}
	store.playbooks[id] = pb
	return pb
}

// ---------------------------------------------------------------------------
// Service-unavailable guard: every playbook route must 503 when the service
// is not wired (nil), rather than panicking on a nil pointer dereference.
// ---------------------------------------------------------------------------

func TestPlaybookRoutes_503WhenServiceUnavailable(t *testing.T) {
	srv, _ := newTestServer() // no Playbooks option set

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/playbooks"},
		{http.MethodPost, "/api/v1/playbooks"},
		{http.MethodGet, "/api/v1/playbooks/pb-1"},
		{http.MethodPatch, "/api/v1/playbooks/pb-1"},
		{http.MethodDelete, "/api/v1/playbooks/pb-1"},
		{http.MethodPost, "/api/v1/playbooks/pb-1/execute"},
		{http.MethodGet, "/api/v1/playbooks/pb-1/executions"},
		{http.MethodGet, "/api/v1/executions/exec-1"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, bytes.NewBufferString("{}"))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: status = %d, want %d", c.method, c.path, rec.Code, http.StatusServiceUnavailable)
		}
	}
}

// ---------------------------------------------------------------------------
// GET /playbooks/{id}
// ---------------------------------------------------------------------------

func TestGetPlaybook_200(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()
	seedPlaybook(store, "pb-1", "Block IP", playbook.PlaybookStatusActive)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/playbooks/pb-1", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var pb playbook.Playbook
	if err := json.NewDecoder(rec.Body).Decode(&pb); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pb.Name != "Block IP" {
		t.Errorf("name = %q, want %q", pb.Name, "Block IP")
	}
}

func TestGetPlaybook_404WhenMissing(t *testing.T) {
	srv, _ := newTestServerWithPlaybooks()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/playbooks/nope", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// PATCH /playbooks/{id}
// ---------------------------------------------------------------------------

func TestPatchPlaybook_200_UpdatesFields(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()
	seedPlaybook(store, "pb-2", "Old Name", playbook.PlaybookStatusDraft)

	body := `{"name":"New Name","status":"active"}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/playbooks/pb-2", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var pb playbook.Playbook
	decodeJSON(t, rec, &pb)
	if pb.Name != "New Name" {
		t.Errorf("name = %q, want %q", pb.Name, "New Name")
	}
	if pb.Status != playbook.PlaybookStatusActive {
		t.Errorf("status = %q, want %q", pb.Status, playbook.PlaybookStatusActive)
	}
	// Verify persisted, not just returned.
	stored := store.playbooks["pb-2"]
	if stored.Name != "New Name" {
		t.Errorf("stored name = %q, want %q", stored.Name, "New Name")
	}
}

func TestPatchPlaybook_404WhenMissing(t *testing.T) {
	srv, _ := newTestServerWithPlaybooks()

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/playbooks/nope", bytes.NewBufferString(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestPatchPlaybook_400OnInvalidJSON(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()
	seedPlaybook(store, "pb-3", "X", playbook.PlaybookStatusDraft)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/playbooks/pb-3", bytes.NewBufferString("not json"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// DELETE /playbooks/{id}
// ---------------------------------------------------------------------------

func TestDeletePlaybook_204(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()
	seedPlaybook(store, "pb-4", "Delete me", playbook.PlaybookStatusDraft)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/playbooks/pb-4", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if _, ok := store.playbooks["pb-4"]; ok {
		t.Error("playbook still present in store after delete")
	}
}

func TestDeletePlaybook_404WhenMissing(t *testing.T) {
	srv, _ := newTestServerWithPlaybooks()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/playbooks/nope", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// POST /playbooks/{id}/execute
// ---------------------------------------------------------------------------

func TestExecutePlaybook_202(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()
	seedPlaybook(store, "pb-5", "Active PB", playbook.PlaybookStatusActive)

	body := `{"incident_id":"inc-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/playbooks/pb-5/execute", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var exec playbook.Execution
	decodeJSON(t, rec, &exec)
	if exec.PlaybookID != "pb-5" || exec.IncidentID != "inc-1" {
		t.Errorf("exec = %+v, want playbook_id=pb-5 incident_id=inc-1", exec)
	}
	if exec.Status != playbook.ExecStatusPending {
		t.Errorf("status = %q, want %q", exec.Status, playbook.ExecStatusPending)
	}
}

func TestExecutePlaybook_400WhenIncidentIDMissing(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()
	seedPlaybook(store, "pb-6", "Active PB", playbook.PlaybookStatusActive)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/playbooks/pb-6/execute", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestExecutePlaybook_400WhenPlaybookNotActive(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()
	seedPlaybook(store, "pb-7", "Draft PB", playbook.PlaybookStatusDraft)

	body := `{"incident_id":"inc-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/playbooks/pb-7/execute", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestExecutePlaybook_404WhenPlaybookMissing(t *testing.T) {
	srv, _ := newTestServerWithPlaybooks()

	body := `{"incident_id":"inc-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/playbooks/nope/execute", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// GET /playbooks/{id}/executions and GET /executions/{id}
// ---------------------------------------------------------------------------

func TestListExecutions_200(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()
	seedPlaybook(store, "pb-8", "PB", playbook.PlaybookStatusActive)
	store.executions["exec-1"] = &playbook.Execution{ID: "exec-1", PlaybookID: "pb-8", IncidentID: "inc-1", Status: playbook.ExecStatusCompleted}
	store.executions["exec-2"] = &playbook.Execution{ID: "exec-2", PlaybookID: "other-pb", IncidentID: "inc-2", Status: playbook.ExecStatusCompleted}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/playbooks/pb-8/executions", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var execs []playbook.Execution
	decodeJSON(t, rec, &execs)
	if len(execs) != 1 {
		t.Fatalf("got %d executions, want 1 (must filter by playbook_id)", len(execs))
	}
	if execs[0].ID != "exec-1" {
		t.Errorf("execution ID = %q, want exec-1", execs[0].ID)
	}
}

func TestGetExecution_200(t *testing.T) {
	srv, store := newTestServerWithPlaybooks()
	store.executions["exec-9"] = &playbook.Execution{ID: "exec-9", PlaybookID: "pb-9", IncidentID: "inc-9", Status: playbook.ExecStatusRunning}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/executions/exec-9", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var exec playbook.Execution
	decodeJSON(t, rec, &exec)
	if exec.Status != playbook.ExecStatusRunning {
		t.Errorf("status = %q, want %q", exec.Status, playbook.ExecStatusRunning)
	}
}

func TestGetExecution_404WhenMissing(t *testing.T) {
	srv, _ := newTestServerWithPlaybooks()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/executions/nope", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// GET /incidents/{id}/actions -- filters the timeline to action entries only.
// ---------------------------------------------------------------------------

func TestListActions_FiltersToActionEntries(t *testing.T) {
	srv, store := newTestServer()
	seedIncident(store, "inc-actions", "Actions test", incident.SeverityP2)
	store.timeline["inc-actions"] = []incident.TimelineEntry{
		{ID: "tl-1", IncidentID: "inc-actions", EntryType: "status_change", Summary: "Opened"},
		{ID: "tl-2", IncidentID: "inc-actions", EntryType: "action", Summary: "Blocked IP"},
		{ID: "tl-3", IncidentID: "inc-actions", EntryType: "action", Summary: "Quarantined host"},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc-actions/actions", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var entries []map[string]interface{}
	decodeJSON(t, rec, &entries)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (only entry_type=action)", len(entries))
	}
	for _, e := range entries {
		if e["entry_type"] != "action" {
			t.Errorf("entry_type = %v, want action", e["entry_type"])
		}
	}
}
