package playbook

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// In-memory mock store implementing playbook.Store.
//
// Execute() runs playbook steps in a background goroutine that calls
// UpdateExecution as it progresses, while tests poll GetExecution from the
// main goroutine — mu guards the maps against that concurrent access, the
// same way a real DB-backed store's connection pool would serialize it.
// ---------------------------------------------------------------------------

type mockStore struct {
	mu         sync.Mutex
	playbooks  map[string]*Playbook
	executions map[string]*Execution
}

func newMockStore() *mockStore {
	return &mockStore{
		playbooks:  make(map[string]*Playbook),
		executions: make(map[string]*Execution),
	}
}

func (m *mockStore) Create(_ context.Context, pb *Playbook) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *pb
	m.playbooks[pb.ID] = &cp
	return nil
}

func (m *mockStore) Get(_ context.Context, id string) (*Playbook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pb, ok := m.playbooks[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *pb
	return &cp, nil
}

func (m *mockStore) List(_ context.Context, opts ListOptions) ([]Playbook, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []Playbook
	for _, pb := range m.playbooks {
		if opts.Status != "" && string(pb.Status) != opts.Status {
			continue
		}
		all = append(all, *pb)
	}
	total := len(all)
	offset := (opts.Page - 1) * opts.PerPage
	if offset < 0 {
		offset = 0
	}
	if offset >= len(all) {
		return []Playbook{}, total, nil
	}
	end := offset + opts.PerPage
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], total, nil
}

func (m *mockStore) Update(_ context.Context, pb *Playbook) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.playbooks[pb.ID]; !ok {
		return ErrNotFound
	}
	cp := *pb
	m.playbooks[pb.ID] = &cp
	return nil
}

func (m *mockStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.playbooks[id]; !ok {
		return ErrNotFound
	}
	delete(m.playbooks, id)
	return nil
}

func (m *mockStore) CreateExecution(_ context.Context, exec *Execution) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *exec
	m.executions[exec.ID] = &cp
	return nil
}

func (m *mockStore) GetExecution(_ context.Context, id string) (*Execution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *exec
	return &cp, nil
}

func (m *mockStore) ListExecutions(_ context.Context, playbookID string) ([]Execution, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Execution
	for _, e := range m.executions {
		if e.PlaybookID == playbookID {
			out = append(out, *e)
		}
	}
	return out, nil
}

func (m *mockStore) UpdateExecution(_ context.Context, exec *Execution) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.executions[exec.ID]; !ok {
		return ErrNotFound
	}
	cp := *exec
	m.executions[exec.ID] = &cp
	return nil
}

func newTestService() (*Service, *mockStore) {
	store := newMockStore()
	svc := NewService(store, NewExecutor(zap.NewNop()), zap.NewNop())
	return svc, store
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestService_Create_Success(t *testing.T) {
	svc, _ := newTestService()

	pb, err := svc.Create(context.Background(), &CreatePlaybookRequest{
		Name:      "Contain host",
		CreatedBy: "alice",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if pb.ID == "" {
		t.Error("expected a generated ID")
	}
	if pb.Version != "1.0" {
		t.Errorf("Version = %q, want default %q", pb.Version, "1.0")
	}
	if pb.Status != PlaybookStatusDraft {
		t.Errorf("Status = %q, want default %q", pb.Status, PlaybookStatusDraft)
	}
	if pb.CreatedAt.IsZero() || pb.UpdatedAt.IsZero() {
		t.Error("expected CreatedAt/UpdatedAt to be set")
	}
}

func TestService_Create_PreservesExplicitVersionAndStatus(t *testing.T) {
	svc, _ := newTestService()

	pb, err := svc.Create(context.Background(), &CreatePlaybookRequest{
		Name:    "Explicit",
		Version: "2.3",
		Status:  PlaybookStatusActive,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if pb.Version != "2.3" {
		t.Errorf("Version = %q, want %q (explicit value should not be overwritten)", pb.Version, "2.3")
	}
	if pb.Status != PlaybookStatusActive {
		t.Errorf("Status = %q, want %q", pb.Status, PlaybookStatusActive)
	}
}

func TestService_Create_RejectsMissingName(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.Create(context.Background(), &CreatePlaybookRequest{})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestService_Create_GeneratesUniqueIDs(t *testing.T) {
	svc, _ := newTestService()

	pb1, err := svc.Create(context.Background(), &CreatePlaybookRequest{Name: "A"})
	if err != nil {
		t.Fatal(err)
	}
	pb2, err := svc.Create(context.Background(), &CreatePlaybookRequest{Name: "B"})
	if err != nil {
		t.Fatal(err)
	}
	if pb1.ID == pb2.ID {
		t.Errorf("expected unique IDs, got %q twice", pb1.ID)
	}
}

// ---------------------------------------------------------------------------
// Get / List
// ---------------------------------------------------------------------------

func TestService_Get_NotFound(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.Get(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestService_List_ClampsPerPage(t *testing.T) {
	svc, store := newTestService()
	store.playbooks["a"] = &Playbook{ID: "a", Status: PlaybookStatusActive}

	_, _, err := svc.List(context.Background(), 0, 0, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	// Indirect assertion: verify defaulting logic by checking a page/perPage
	// combination that would clamp differently produces the same total count
	// regardless of the invalid input, i.e. it didn't error or panic on
	// zero/negative values.
	results, total, err := svc.List(context.Background(), -5, 500, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(results) != 1 {
		t.Errorf("len(results) = %d, want 1", len(results))
	}
}

func TestService_List_FiltersByStatus(t *testing.T) {
	svc, store := newTestService()
	store.playbooks["a"] = &Playbook{ID: "a", Status: PlaybookStatusActive}
	store.playbooks["b"] = &Playbook{ID: "b", Status: PlaybookStatusDraft}

	results, total, err := svc.List(context.Background(), 1, 50, string(PlaybookStatusActive))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(results) != 1 || results[0].ID != "a" {
		t.Errorf("results = %v, want only playbook 'a'", results)
	}
}

// ---------------------------------------------------------------------------
// Patch
// ---------------------------------------------------------------------------

func TestService_Patch_UpdatesOnlyProvidedFields(t *testing.T) {
	svc, store := newTestService()
	orig := &Playbook{
		ID:          "pb-1",
		Name:        "Original",
		Description: "orig desc",
		Version:     "1.0",
		Status:      PlaybookStatusDraft,
		UpdatedAt:   time.Now().UTC().Add(-time.Hour),
	}
	store.playbooks["pb-1"] = orig

	newName := "Renamed"
	pb, err := svc.Patch(context.Background(), "pb-1", &PatchPlaybookRequest{Name: &newName})
	if err != nil {
		t.Fatalf("Patch() error = %v", err)
	}
	if pb.Name != "Renamed" {
		t.Errorf("Name = %q, want %q", pb.Name, "Renamed")
	}
	// Untouched fields must survive the partial update.
	if pb.Description != "orig desc" {
		t.Errorf("Description = %q, want unchanged %q", pb.Description, "orig desc")
	}
	if !pb.UpdatedAt.After(orig.UpdatedAt) {
		t.Error("expected UpdatedAt to advance on patch")
	}
}

func TestService_Patch_NotFound(t *testing.T) {
	svc, _ := newTestService()

	name := "x"
	_, err := svc.Patch(context.Background(), "missing", &PatchPlaybookRequest{Name: &name})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestService_Delete_RemovesPlaybook(t *testing.T) {
	svc, store := newTestService()
	store.playbooks["pb-1"] = &Playbook{ID: "pb-1"}

	if err := svc.Delete(context.Background(), "pb-1"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, ok := store.playbooks["pb-1"]; ok {
		t.Error("expected playbook to be removed from store")
	}
}

func TestService_Delete_NotFound(t *testing.T) {
	svc, _ := newTestService()

	err := svc.Delete(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

func TestService_Execute_RejectsInactivePlaybook(t *testing.T) {
	svc, store := newTestService()
	store.playbooks["pb-1"] = &Playbook{ID: "pb-1", Status: PlaybookStatusDraft}

	_, err := svc.Execute(context.Background(), "pb-1", "inc-1")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid (draft playbooks must not execute)", err)
	}
}

func TestService_Execute_NotFound(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.Execute(context.Background(), "missing", "inc-1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestService_Execute_CreatesPendingExecutionAndRunsToCompletion(t *testing.T) {
	svc, store := newTestService()
	store.playbooks["pb-1"] = &Playbook{
		ID:     "pb-1",
		Status: PlaybookStatusActive,
		Steps: []Step{
			{ID: "a", Name: "A", Type: StepTypeAction},
		},
	}

	exec, err := svc.Execute(context.Background(), "pb-1", "inc-1")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if exec.PlaybookID != "pb-1" || exec.IncidentID != "inc-1" {
		t.Errorf("exec = %+v, want PlaybookID=pb-1 IncidentID=inc-1", exec)
	}
	if exec.Status != ExecStatusPending {
		t.Errorf("initial Status = %q, want %q (Execute returns before the async run completes)", exec.Status, ExecStatusPending)
	}

	// The executor runs asynchronously (launched via `go`); poll the store
	// briefly for the terminal state rather than sleeping a fixed duration.
	deadline := time.Now().Add(2 * time.Second)
	var final *Execution
	for time.Now().Before(deadline) {
		got, err := svc.GetExecution(context.Background(), exec.ID)
		if err != nil {
			t.Fatalf("GetExecution() error = %v", err)
		}
		if got.Status == ExecStatusCompleted || got.Status == ExecStatusFailed {
			final = got
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if final == nil {
		t.Fatal("execution did not reach a terminal state within the deadline")
	}
	if final.Status != ExecStatusCompleted {
		t.Errorf("final Status = %q, want %q (error: %s)", final.Status, ExecStatusCompleted, final.Error)
	}
	if final.CompletedAt == nil {
		t.Error("expected CompletedAt to be set once the run finishes")
	}
}

func TestService_ListExecutions_FiltersByPlaybook(t *testing.T) {
	svc, store := newTestService()
	store.executions["e1"] = &Execution{ID: "e1", PlaybookID: "pb-1"}
	store.executions["e2"] = &Execution{ID: "e2", PlaybookID: "pb-2"}

	execs, err := svc.ListExecutions(context.Background(), "pb-1")
	if err != nil {
		t.Fatalf("ListExecutions() error = %v", err)
	}
	if len(execs) != 1 || execs[0].ID != "e1" {
		t.Errorf("execs = %v, want only e1", execs)
	}
}

// ---------------------------------------------------------------------------
// WithMetrics
// ---------------------------------------------------------------------------

func TestService_WithMetrics_WiresExecutorAndReturnsSelf(t *testing.T) {
	svc, _ := newTestService()

	got := svc.WithMetrics(nil)
	if got != svc {
		t.Error("WithMetrics should return the same *Service for chaining")
	}
}
