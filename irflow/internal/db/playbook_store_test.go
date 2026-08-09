package db

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"

	"github.com/opensecstack/opensecstack/irflow/internal/playbook"
)

func anyPlaybookArgs(n int) []interface{} {
	out := make([]interface{}, n)
	for i := range out {
		out[i] = pgxmock.AnyArg()
	}
	return out
}

func newMockPlaybookStore(t *testing.T) (*PGPlaybookStore, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("creating pgxmock pool: %v", err)
	}
	t.Cleanup(mock.Close)
	return &PGPlaybookStore{pool: mock}, mock
}

func TestPGPlaybookStore_Create_Success(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	mock.ExpectExec("INSERT INTO playbooks").
		WithArgs(anyPlaybookArgs(10)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	pb := &playbook.Playbook{
		ID:      "pb-1",
		Name:    "Contain and notify",
		Status:  playbook.PlaybookStatusDraft,
		Trigger: playbook.Trigger{EventType: "apiguard.finding.critical"},
		Steps:   []playbook.Step{{ID: "s1", Type: playbook.StepTypeAction}},
	}
	if err := store.Create(context.Background(), pb); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPGPlaybookStore_Get_NotFoundMapsToDomainError(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	mock.ExpectQuery("SELECT (.|\n)*FROM playbooks").
		WithArgs("missing").
		WillReturnError(pgx.ErrNoRows)

	_, err := store.Get(context.Background(), "missing")
	if err != playbook.ErrNotFound {
		t.Fatalf("expected playbook.ErrNotFound, got %v", err)
	}
}

func TestPGPlaybookStore_Get_UnmarshalsTriggerAndSteps(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	rows := pgxmock.NewRows([]string{
		"id", "name", "description", "version", "status", "trigger", "steps",
		"created_by", "created_at", "updated_at",
	}).AddRow(
		"pb-1", "Name", "desc", "1", playbook.PlaybookStatusActive,
		[]byte(`{"event_type":"x.y","severity":"P1"}`),
		[]byte(`[{"id":"s1","type":"action"}]`),
		"user-1", time.Now(), time.Now(),
	)
	mock.ExpectQuery("SELECT (.|\n)*FROM playbooks").
		WithArgs("pb-1").
		WillReturnRows(rows)

	pb, err := store.Get(context.Background(), "pb-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pb.Trigger.EventType != "x.y" || pb.Trigger.Severity != "P1" {
		t.Errorf("unexpected trigger unmarshalled: %+v", pb.Trigger)
	}
	if len(pb.Steps) != 1 || pb.Steps[0].ID != "s1" {
		t.Errorf("unexpected steps unmarshalled: %+v", pb.Steps)
	}
}

func TestPGPlaybookStore_Get_InvalidTriggerJSONReturnsError(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	rows := pgxmock.NewRows([]string{
		"id", "name", "description", "version", "status", "trigger", "steps",
		"created_by", "created_at", "updated_at",
	}).AddRow(
		"pb-1", "Name", "desc", "1", playbook.PlaybookStatusActive,
		[]byte(`not-json`),
		[]byte(`[]`),
		"user-1", time.Now(), time.Now(),
	)
	mock.ExpectQuery("SELECT (.|\n)*FROM playbooks").
		WithArgs("pb-1").
		WillReturnRows(rows)

	_, err := store.Get(context.Background(), "pb-1")
	if err == nil {
		t.Fatal("expected error when trigger column is not valid JSON")
	}
}

func TestPGPlaybookStore_Update_NoRowsAffectedReturnsNotFound(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	mock.ExpectExec("UPDATE playbooks SET").
		WithArgs(anyPlaybookArgs(8)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.Update(context.Background(), &playbook.Playbook{ID: "missing"})
	if err != playbook.ErrNotFound {
		t.Fatalf("expected playbook.ErrNotFound, got %v", err)
	}
}

func TestPGPlaybookStore_Delete_NoRowsAffectedReturnsNotFound(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	mock.ExpectExec("DELETE FROM playbooks").
		WithArgs("missing").
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	err := store.Delete(context.Background(), "missing")
	if err != playbook.ErrNotFound {
		t.Fatalf("expected playbook.ErrNotFound, got %v", err)
	}
}

func TestPGPlaybookStore_Delete_Success(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	mock.ExpectExec("DELETE FROM playbooks").
		WithArgs("pb-1").
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	if err := store.Delete(context.Background(), "pb-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPGPlaybookStore_List_FiltersByStatus(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM playbooks WHERE status = \\$1").
		WithArgs("active").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT (.|\n)*FROM playbooks WHERE status = \\$1").
		WithArgs("active", 20, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "name", "description", "version", "status", "trigger", "steps",
			"created_by", "created_at", "updated_at",
		}))

	_, total, err := store.List(context.Background(), playbook.ListOptions{Page: 1, PerPage: 20, Status: "active"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (status filter not applied as expected): %v", err)
	}
}

func TestPGPlaybookStore_CreateExecution_MarshalsStepResults(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	mock.ExpectExec("INSERT INTO playbook_executions").
		WithArgs(anyPlaybookArgs(9)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	exec := &playbook.Execution{
		ID:         "exec-1",
		PlaybookID: "pb-1",
		Status:     playbook.ExecStatusRunning,
		StepResults: []playbook.StepResult{
			{StepID: "s1", Status: "success"},
		},
	}
	if err := store.CreateExecution(context.Background(), exec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPGPlaybookStore_GetExecution_NotFoundMapsToDomainError(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	mock.ExpectQuery("SELECT (.|\n)*FROM playbook_executions").
		WithArgs("missing").
		WillReturnError(pgx.ErrNoRows)

	_, err := store.GetExecution(context.Background(), "missing")
	if err != playbook.ErrNotFound {
		t.Fatalf("expected playbook.ErrNotFound, got %v", err)
	}
}

func TestPGPlaybookStore_UpdateExecution_NoRowsAffectedReturnsNotFound(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	mock.ExpectExec("UPDATE playbook_executions SET").
		WithArgs(anyPlaybookArgs(6)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.UpdateExecution(context.Background(), &playbook.Execution{ID: "missing"})
	if err != playbook.ErrNotFound {
		t.Fatalf("expected playbook.ErrNotFound, got %v", err)
	}
}

func TestPGPlaybookStore_ListExecutions_ReturnsEmptySliceNotNil(t *testing.T) {
	store, mock := newMockPlaybookStore(t)

	mock.ExpectQuery("SELECT (.|\n)*FROM playbook_executions").
		WithArgs("pb-1").
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "playbook_id", "incident_id", "status", "current_step",
			"step_results", "error", "started_at", "completed_at",
		}))

	execs, err := store.ListExecutions(context.Background(), "pb-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if execs == nil {
		t.Error("expected ListExecutions to return an empty slice, not nil")
	}
}
