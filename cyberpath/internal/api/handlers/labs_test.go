// Integration tests for LabsHandler.
// White-box style: same package as the handlers under test.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/opensecstack/cyberpath/internal/db"
)

// ── fake stores ───────────────────────────────────────────────────────────────

// fakeLabSessionManager implements LabSessionManager entirely in memory.
type fakeLabSessionManager struct {
	mu sync.Mutex

	// Configurable return values.
	def     *db.LabDefinition
	defErr  error
	session *db.LabSession
	sesErr  error
	endErr  error
	getErr  error
	metaErr error

	// Call tracking.
	endSessionCalls    []string   // status values passed to EndSession
	updateMetaCalls    []uuid.UUID
	updateMetaPayloads []json.RawMessage
}

func (m *fakeLabSessionManager) GetDefinition(_ context.Context, id string) (*db.LabDefinition, error) {
	if m.defErr != nil {
		return nil, m.defErr
	}
	if m.def != nil {
		return m.def, nil
	}
	return &db.LabDefinition{ID: id, Runtime: "browser", TimeLimitSeconds: 3600}, nil
}

func (m *fakeLabSessionManager) StartSession(_ context.Context, labID string, userID uuid.UUID, cohortID *uuid.UUID, tenantID uuid.UUID) (*db.LabSession, error) {
	if m.sesErr != nil {
		return nil, m.sesErr
	}
	if m.session != nil {
		return m.session, nil
	}
	runtime := "browser"
	if m.def != nil {
		runtime = m.def.Runtime
	}
	return &db.LabSession{
		ID:        uuid.New(),
		LabID:     labID,
		UserID:    userID,
		Status:    "running",
		Runtime:   runtime,
		StartedAt: time.Now(),
	}, nil
}

func (m *fakeLabSessionManager) EndSession(_ context.Context, sessionID uuid.UUID, status string, _ json.RawMessage, _ *int, _, _ string) error {
	m.mu.Lock()
	m.endSessionCalls = append(m.endSessionCalls, status)
	m.mu.Unlock()
	return m.endErr
}

func (m *fakeLabSessionManager) GetSession(_ context.Context, id uuid.UUID) (*db.LabSession, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.session != nil {
		return m.session, nil
	}
	return &db.LabSession{
		ID:        id,
		LabID:     "test-lab",
		Status:    "running",
		StartedAt: time.Now(),
	}, nil
}

func (m *fakeLabSessionManager) UpdateMetadata(_ context.Context, sessionID uuid.UUID, metadata json.RawMessage) error {
	m.mu.Lock()
	m.updateMetaCalls = append(m.updateMetaCalls, sessionID)
	m.updateMetaPayloads = append(m.updateMetaPayloads, metadata)
	m.mu.Unlock()
	return m.metaErr
}

// fakeDockerProvisioner implements DockerProvisioner.
type fakeDockerProvisioner struct {
	mu sync.Mutex

	containerID    string
	startErr       error
	stopErr        error
	stopCalls      []string // container IDs passed to StopContainer
}

func newFakeDockerProvisioner() *fakeDockerProvisioner {
	return &fakeDockerProvisioner{containerID: "container-abc"}
}

func (d *fakeDockerProvisioner) StartContainer(_ context.Context, _ *db.LabDefinition, _ string) (string, error) {
	if d.startErr != nil {
		return "", d.startErr
	}
	return d.containerID, nil
}

func (d *fakeDockerProvisioner) StopContainer(_ context.Context, containerID string) error {
	d.mu.Lock()
	d.stopCalls = append(d.stopCalls, containerID)
	d.mu.Unlock()
	return d.stopErr
}

// ── Start tests ───────────────────────────────────────────────────────────────

func TestLabsStart_NoDocker_Success(t *testing.T) {
	userID := uuid.New()
	mgr := &fakeLabSessionManager{}
	h := &LabsHandler{Labs: mgr}

	r := chi.NewRouter()
	r.Post("/labs/{id}/start", h.Start)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/labs/intro-to-linux/start", nil), userID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["status"] == nil {
		t.Errorf("missing 'status' in response: %v", body)
	}
	if body["session_id"] == nil || body["session_id"] == "" {
		t.Errorf("missing 'session_id' in response: %v", body)
	}
}

func TestLabsStart_WithDocker_Success(t *testing.T) {
	userID := uuid.New()
	def := &db.LabDefinition{ID: "docker-lab", Runtime: "docker", TimeLimitSeconds: 1800}
	mgr := &fakeLabSessionManager{def: def}
	docker := newFakeDockerProvisioner()
	h := &LabsHandler{Labs: mgr, Docker: docker}

	r := chi.NewRouter()
	r.Post("/labs/{id}/start", h.Start)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/labs/docker-lab/start", nil), userID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body: %s", w.Code, w.Body.String())
	}
	// UpdateMetadata must have been called with a container_id payload.
	mgr.mu.Lock()
	metaCalls := len(mgr.updateMetaCalls)
	mgr.mu.Unlock()
	if metaCalls == 0 {
		t.Errorf("UpdateMetadata was not called after docker container start")
	}
}

func TestLabsStart_LabNotFound(t *testing.T) {
	userID := uuid.New()
	mgr := &fakeLabSessionManager{defErr: pgx.ErrNoRows}
	h := &LabsHandler{Labs: mgr}

	r := chi.NewRouter()
	r.Post("/labs/{id}/start", h.Start)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/labs/missing-lab/start", nil), userID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

func TestLabsStart_Unauthorized(t *testing.T) {
	mgr := &fakeLabSessionManager{}
	h := &LabsHandler{Labs: mgr}

	r := chi.NewRouter()
	r.Post("/labs/{id}/start", h.Start)

	// No user context.
	req := httptest.NewRequest(http.MethodPost, "/labs/some-lab/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", w.Code, w.Body.String())
	}
}

func TestLabsStart_DockerFails_RollsBackSession(t *testing.T) {
	userID := uuid.New()
	def := &db.LabDefinition{ID: "docker-lab", Runtime: "docker"}
	mgr := &fakeLabSessionManager{def: def}
	docker := &fakeDockerProvisioner{startErr: fmt.Errorf("docker daemon unreachable")}
	h := &LabsHandler{Labs: mgr, Docker: docker}

	r := chi.NewRouter()
	r.Post("/labs/{id}/start", h.Start)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/labs/docker-lab/start", nil), userID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
	// EndSession should have been called with status "failed" to roll back.
	mgr.mu.Lock()
	calls := append([]string(nil), mgr.endSessionCalls...)
	mgr.mu.Unlock()
	if len(calls) == 0 {
		t.Fatalf("EndSession was not called after Docker failure")
	}
	if calls[0] != "failed" {
		t.Errorf("EndSession status = %q, want \"failed\"", calls[0])
	}
}

// ── Stop tests ────────────────────────────────────────────────────────────────

func TestLabsStop_Success(t *testing.T) {
	sessionID := uuid.New()
	mgr := &fakeLabSessionManager{}
	h := &LabsHandler{Labs: mgr}

	r := chi.NewRouter()
	r.Post("/labs/{id}/stop", h.Stop)

	req := httptest.NewRequest(http.MethodPost, "/labs/"+sessionID.String()+"/stop", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["status"] != "cancelled" {
		t.Errorf("status = %v, want 'cancelled'", body["status"])
	}
}

func TestLabsStop_InvalidID(t *testing.T) {
	mgr := &fakeLabSessionManager{}
	h := &LabsHandler{Labs: mgr}

	r := chi.NewRouter()
	r.Post("/labs/{id}/stop", h.Stop)

	req := httptest.NewRequest(http.MethodPost, "/labs/not-a-uuid/stop", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestLabsStop_WithDocker_StopsContainer(t *testing.T) {
	sessionID := uuid.New()
	// Session with metadata containing a container_id.
	meta, _ := json.Marshal(map[string]string{"container_id": "ctr-1"})
	sess := &db.LabSession{
		ID:        sessionID,
		LabID:     "docker-lab",
		Status:    "running",
		StartedAt: time.Now(),
		Metadata:  meta,
	}
	mgr := &fakeLabSessionManager{session: sess}
	docker := newFakeDockerProvisioner()
	h := &LabsHandler{Labs: mgr, Docker: docker}

	r := chi.NewRouter()
	r.Post("/labs/{id}/stop", h.Stop)

	req := httptest.NewRequest(http.MethodPost, "/labs/"+sessionID.String()+"/stop", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	docker.mu.Lock()
	stops := append([]string(nil), docker.stopCalls...)
	docker.mu.Unlock()
	if len(stops) == 0 {
		t.Fatalf("StopContainer was not called")
	}
	if stops[0] != "ctr-1" {
		t.Errorf("StopContainer called with %q, want \"ctr-1\"", stops[0])
	}
}

// ── Status tests ──────────────────────────────────────────────────────────────

func TestLabsStatus_Success(t *testing.T) {
	sessionID := uuid.New()
	mgr := &fakeLabSessionManager{}
	h := &LabsHandler{Labs: mgr}

	r := chi.NewRouter()
	r.Get("/labs/{id}/status", h.Status)

	req := httptest.NewRequest(http.MethodGet, "/labs/"+sessionID.String()+"/status", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["session_id"] == nil || body["session_id"] == "" {
		t.Errorf("missing 'session_id' in response: %v", body)
	}
}

func TestLabsStatus_NotFound(t *testing.T) {
	sessionID := uuid.New()
	mgr := &fakeLabSessionManager{getErr: pgx.ErrNoRows}
	h := &LabsHandler{Labs: mgr}

	r := chi.NewRouter()
	r.Get("/labs/{id}/status", h.Status)

	req := httptest.NewRequest(http.MethodGet, "/labs/"+sessionID.String()+"/status", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

func TestLabsStatus_InvalidID(t *testing.T) {
	mgr := &fakeLabSessionManager{}
	h := &LabsHandler{Labs: mgr}

	r := chi.NewRouter()
	r.Get("/labs/{id}/status", h.Status)

	req := httptest.NewRequest(http.MethodGet, "/labs/not-a-uuid/status", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}
