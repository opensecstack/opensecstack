//go:build integration

package db

import (
	"context"
	"testing"
	"time"

	"github.com/opensecstack/opensecstack/irflow/internal/playbook"
)

func samplePlaybook(id string) *playbook.Playbook {
	return &playbook.Playbook{
		ID:          id,
		Name:        "Critical Finding Response",
		Description: "auto-response",
		Version:     "1.0",
		Status:      playbook.PlaybookStatusActive,
		CreatedBy:   "ops",
		Trigger: playbook.Trigger{
			EventType: "apiguard.finding.critical",
			Severity:  "P1",
		},
		Steps: []playbook.Step{
			{ID: "a", Name: "create", Type: playbook.StepTypeAction, OnSuccess: "b"},
			{ID: "b", Name: "notify", Type: playbook.StepTypeNotify},
		},
	}
}

func TestPGPlaybookStore_CRUD(t *testing.T) {
	pool := setupDB(t)
	store := NewPGPlaybookStore(pool)
	ctx := context.Background()

	pb := samplePlaybook("pb-1")
	if err := store.Create(ctx, pb); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(ctx, "pb-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Trigger.EventType != "apiguard.finding.critical" {
		t.Errorf("Trigger round-trip failed: %+v", got.Trigger)
	}
	if len(got.Steps) != 2 || got.Steps[0].OnSuccess != "b" {
		t.Errorf("Steps round-trip failed: %+v", got.Steps)
	}

	got.Name = "renamed"
	got.Status = playbook.PlaybookStatusArchived
	if err := store.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	after, _ := store.Get(ctx, "pb-1")
	if after.Name != "renamed" || after.Status != playbook.PlaybookStatusArchived {
		t.Errorf("post-update: %+v", after)
	}

	if err := store.Delete(ctx, "pb-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "pb-1"); err != playbook.ErrNotFound {
		t.Errorf("after delete: err = %v, want ErrNotFound", err)
	}
}

func TestPGPlaybookStore_ListWithStatusFilter(t *testing.T) {
	pool := setupDB(t)
	store := NewPGPlaybookStore(pool)
	ctx := context.Background()

	active := samplePlaybook("pb-active")
	active.Status = playbook.PlaybookStatusActive
	draft := samplePlaybook("pb-draft")
	draft.Status = playbook.PlaybookStatusDraft
	_ = store.Create(ctx, active)
	_ = store.Create(ctx, draft)

	all, total, err := store.List(ctx, playbook.ListOptions{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(all) != 2 {
		t.Errorf("List all: total=%d len=%d, want 2/2", total, len(all))
	}

	activeOnly, total, err := store.List(ctx, playbook.ListOptions{Page: 1, PerPage: 10, Status: string(playbook.PlaybookStatusActive)})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(activeOnly) != 1 || activeOnly[0].ID != "pb-active" {
		t.Errorf("List active: total=%d results=%+v", total, activeOnly)
	}
}

func TestPGPlaybookStore_ExecutionLifecycle(t *testing.T) {
	pool := setupDB(t)
	store := NewPGPlaybookStore(pool)
	ctx := context.Background()

	pb := samplePlaybook("pb-ex")
	if err := store.Create(ctx, pb); err != nil {
		t.Fatal(err)
	}

	exec := &playbook.Execution{
		ID:         "exec-1",
		PlaybookID: "pb-ex",
		IncidentID: "inc-parent",
		Status:     playbook.ExecStatusPending,
		StartedAt:  time.Now().UTC(),
	}
	if err := store.CreateExecution(ctx, exec); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}

	exec.Status = playbook.ExecStatusCompleted
	exec.CurrentStep = "b"
	exec.StepResults = []playbook.StepResult{
		{StepID: "a", Status: "success", Output: "ok"},
		{StepID: "b", Status: "success", Output: "notify sent"},
	}
	now := time.Now().UTC()
	exec.CompletedAt = &now
	if err := store.UpdateExecution(ctx, exec); err != nil {
		t.Fatalf("UpdateExecution: %v", err)
	}

	got, err := store.GetExecution(ctx, "exec-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != playbook.ExecStatusCompleted {
		t.Errorf("status = %s, want completed", got.Status)
	}
	if len(got.StepResults) != 2 {
		t.Fatalf("step results round-trip failed: %+v", got.StepResults)
	}
	if got.StepResults[1].Output != "notify sent" {
		t.Errorf("step result content: %+v", got.StepResults[1])
	}

	list, err := store.ListExecutions(ctx, "pb-ex")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("ListExecutions: got %d, want 1", len(list))
	}
}

func TestPGPlaybookStore_ExecutionCascadesOnPlaybookDelete(t *testing.T) {
	pool := setupDB(t)
	store := NewPGPlaybookStore(pool)
	ctx := context.Background()

	_ = store.Create(ctx, samplePlaybook("pb-cascade"))
	_ = store.CreateExecution(ctx, &playbook.Execution{
		ID: "e1", PlaybookID: "pb-cascade", IncidentID: "inc", Status: playbook.ExecStatusPending, StartedAt: time.Now(),
	})

	if err := store.Delete(ctx, "pb-cascade"); err != nil {
		t.Fatal(err)
	}
	execs, _ := store.ListExecutions(ctx, "pb-cascade")
	if len(execs) != 0 {
		t.Errorf("expected cascade delete, got %d executions", len(execs))
	}
}
