package db

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v3"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
)

// newMockStore creates a PGStore backed by a pgxmock pool, plus the mock so
// the test can set expectations and assert they were met.
func newMockStore(t *testing.T) (*PGStore, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("creating pgxmock pool: %v", err)
	}
	t.Cleanup(mock.Close)
	return &PGStore{pool: mock}, mock
}

// anyArgs returns n wildcard argument matchers, for statements whose exact
// bind values are not under test but whose count still must line up with
// pgxmock's strict arity check.
func anyArgs(n int) []interface{} {
	out := make([]interface{}, n)
	for i := range out {
		out[i] = pgxmock.AnyArg()
	}
	return out
}

func TestPGStore_Create_GeneratesIDAndTimestampsWhenEmpty(t *testing.T) {
	store, mock := newMockStore(t)

	args := anyArgs(19)
	args[1] = "Title"
	args[2] = "desc"
	args[3] = incident.SeverityP1
	args[4] = incident.StatusOpen
	args[5] = incident.SourceManual
	mock.ExpectExec("INSERT INTO incidents").
		WithArgs(args...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	inc := &incident.Incident{
		Title:    "Title",
		Description: "desc",
		Severity: incident.SeverityP1,
		Status:   incident.StatusOpen,
		Source:   incident.SourceManual,
	}
	if err := store.Create(context.Background(), inc); err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	if inc.ID == "" {
		t.Error("expected Create to generate a non-empty ID when none was supplied")
	}
	if inc.CreatedAt.IsZero() {
		t.Error("expected Create to populate CreatedAt")
	}
	if inc.UpdatedAt.IsZero() {
		t.Error("expected Create to populate UpdatedAt")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestPGStore_Create_PreservesSuppliedID(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectExec("INSERT INTO incidents").
		WithArgs(anyArgs(19)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	inc := &incident.Incident{ID: "inc-fixed-1", Title: "t"}
	if err := store.Create(context.Background(), inc); err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if inc.ID != "inc-fixed-1" {
		t.Errorf("expected Create to preserve caller-supplied ID, got %q", inc.ID)
	}
}

func TestPGStore_Create_WrapsExecError(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectExec("INSERT INTO incidents").
		WillReturnError(pgx.ErrTxClosed)

	err := store.Create(context.Background(), &incident.Incident{ID: "inc-1"})
	if err == nil {
		t.Fatal("expected Create to return an error when Exec fails")
	}
}

func TestPGStore_Get_NotFoundMapsToDomainError(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectQuery("SELECT (.|\n)*FROM incidents").
		WithArgs("missing-id").
		WillReturnError(pgx.ErrNoRows)

	_, err := store.Get(context.Background(), "missing-id")
	if err != incident.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPGStore_Get_ReturnsIncidentOnSuccess(t *testing.T) {
	store, mock := newMockStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	rows := pgxmock.NewRows([]string{
		"id", "title", "description", "severity", "status", "source", "source_ref",
		"project_id", "commander_id", "lead_id", "root_cause", "corrective_action",
		"worm_entry_id", "nis2_notify_required", "nis2_notified_at",
		"contained_at", "closed_at", "created_at", "updated_at",
	}).AddRow(
		"inc-1", "Title", "desc", incident.SeverityP2, incident.StatusOpen, incident.SourceManual, "",
		"", "", "", "", "",
		"", false, nil,
		nil, nil, now, now,
	)

	mock.ExpectQuery("SELECT (.|\n)*FROM incidents").
		WithArgs("inc-1").
		WillReturnRows(rows)

	got, err := store.Get(context.Background(), "inc-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "inc-1" || got.Title != "Title" || got.Severity != incident.SeverityP2 {
		t.Errorf("unexpected incident returned: %+v", got)
	}
}

func TestPGStore_Update_NoRowsAffectedReturnsNotFound(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectExec("UPDATE incidents SET").
		WithArgs(anyArgs(18)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.Update(context.Background(), &incident.Incident{ID: "missing"})
	if err != incident.ErrNotFound {
		t.Fatalf("expected ErrNotFound when 0 rows affected, got %v", err)
	}
}

func TestPGStore_Update_SetsUpdatedAt(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectExec("UPDATE incidents SET").
		WithArgs(anyArgs(18)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	inc := &incident.Incident{ID: "inc-1"}
	before := time.Now().UTC()
	if err := store.Update(context.Background(), inc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inc.UpdatedAt.Before(before) {
		t.Errorf("expected UpdatedAt to be refreshed to now, got %v (before test start %v)", inc.UpdatedAt, before)
	}
}

func TestPGStore_Delete_NoRowsAffectedReturnsNotFound(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectExec("DELETE FROM incidents").
		WithArgs("missing").
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	err := store.Delete(context.Background(), "missing")
	if err != incident.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPGStore_Delete_Success(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectExec("DELETE FROM incidents").
		WithArgs("inc-1").
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	if err := store.Delete(context.Background(), "inc-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPGStore_List_BuildsWhereClauseFromFilters verifies that List only adds
// SQL WHERE conditions for the filters that are actually set, and applies
// them in Status, Severity, Source order with the count query first.
func TestPGStore_List_BuildsWhereClauseFromFilters(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM incidents WHERE status = \\$1 AND severity = \\$2").
		WithArgs("open", "P1").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(2))

	mock.ExpectQuery("SELECT (.|\n)*FROM incidents WHERE status = \\$1 AND severity = \\$2").
		WithArgs("open", "P1", 10, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "title", "description", "severity", "status", "source", "source_ref",
			"project_id", "commander_id", "lead_id", "root_cause", "corrective_action",
			"worm_entry_id", "nis2_notify_required", "nis2_notified_at",
			"contained_at", "closed_at", "created_at", "updated_at",
		}))

	results, total, err := store.List(context.Background(), incident.ListOptions{
		Page: 1, PerPage: 10, Status: "open", Severity: "P1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
	if results == nil {
		t.Error("expected non-nil empty slice when there are no rows, got nil")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestPGStore_List_NegativeOffsetClampedToZero verifies that a Page value of
// 0 (or less) never produces a negative SQL OFFSET.
func TestPGStore_List_NegativeOffsetClampedToZero(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM incidents").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT (.|\n)*FROM incidents").
		WithArgs(10, 0).
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "title", "description", "severity", "status", "source", "source_ref",
			"project_id", "commander_id", "lead_id", "root_cause", "corrective_action",
			"worm_entry_id", "nis2_notify_required", "nis2_notified_at",
			"contained_at", "closed_at", "created_at", "updated_at",
		}))

	_, _, err := store.List(context.Background(), incident.ListOptions{Page: 0, PerPage: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (offset was not clamped to 0): %v", err)
	}
}

func TestPGStore_AddAction_GeneratesID(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectExec("INSERT INTO incident_actions").
		WithArgs(anyArgs(10)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	action := &incident.IncidentAction{IncidentID: "inc-1", ActionType: "contain"}
	if err := store.AddAction(context.Background(), action); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action.ID == "" {
		t.Error("expected AddAction to generate a non-empty ID")
	}
}

func TestPGStore_GetPendingAction_NotFoundMapsToDomainError(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectQuery("SELECT (.|\n)*FROM pending_actions").
		WithArgs("missing").
		WillReturnError(pgx.ErrNoRows)

	_, err := store.GetPendingAction(context.Background(), "missing")
	if err != incident.ErrPendingActionNotFound {
		t.Fatalf("expected ErrPendingActionNotFound, got %v", err)
	}
}

func TestPGStore_UpdatePendingAction_NoRowsAffectedReturnsNotFound(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectExec("UPDATE pending_actions SET").
		WithArgs(anyArgs(10)...).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := store.UpdatePendingAction(context.Background(), &incident.PendingAction{ID: "missing"})
	if err != incident.ErrPendingActionNotFound {
		t.Fatalf("expected ErrPendingActionNotFound, got %v", err)
	}
}

func TestPGStore_Stats_AggregatesAllDimensions(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM incidents$").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(5))
	mock.ExpectQuery("SELECT severity, COUNT\\(\\*\\) FROM incidents GROUP BY severity").
		WillReturnRows(pgxmock.NewRows([]string{"severity", "count"}).AddRow("P1", 3).AddRow("P2", 2))
	mock.ExpectQuery("SELECT status, COUNT\\(\\*\\) FROM incidents GROUP BY status").
		WillReturnRows(pgxmock.NewRows([]string{"status", "count"}).AddRow("open", 5))
	mock.ExpectQuery("SELECT source, COUNT\\(\\*\\) FROM incidents GROUP BY source").
		WillReturnRows(pgxmock.NewRows([]string{"source", "count"}).AddRow("manual", 5))

	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Total != 5 {
		t.Errorf("expected Total 5, got %d", stats.Total)
	}
	if stats.BySeverity["P1"] != 3 || stats.BySeverity["P2"] != 2 {
		t.Errorf("unexpected BySeverity: %+v", stats.BySeverity)
	}
	// Unset severities must default to 0, not be missing from the map.
	if stats.BySeverity["P3"] != 0 {
		t.Errorf("expected default P3 count 0, got %d", stats.BySeverity["P3"])
	}
	if stats.ByStatus["open"] != 5 {
		t.Errorf("unexpected ByStatus: %+v", stats.ByStatus)
	}
	if stats.BySource["manual"] != 5 {
		t.Errorf("unexpected BySource: %+v", stats.BySource)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestPGStore_Stats_PropagatesCountError(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM incidents$").
		WillReturnError(pgx.ErrTxClosed)

	_, err := store.Stats(context.Background())
	if err == nil {
		t.Fatal("expected error to propagate from failed count query")
	}
}

func TestPGStore_AddIOC_GeneratesID(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectExec("INSERT INTO ioc_enrichments").
		WithArgs(anyArgs(8)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	ioc := &incident.IOCEnrichment{IncidentID: "inc-1", IOCType: "ip", IOCValue: "1.2.3.4"}
	if err := store.AddIOC(context.Background(), ioc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ioc.ID == "" {
		t.Error("expected AddIOC to generate a non-empty ID")
	}
}

func TestPGStore_AddTimelineEntry_GeneratesID(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectExec("INSERT INTO timeline_entries").
		WithArgs(anyArgs(7)...).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	entry := &incident.TimelineEntry{IncidentID: "inc-1", EntryType: "note"}
	if err := store.AddTimelineEntry(context.Background(), entry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.ID == "" {
		t.Error("expected AddTimelineEntry to generate a non-empty ID")
	}
}

func TestPGStore_ListActions_ReturnsEmptySliceNotNil(t *testing.T) {
	store, mock := newMockStore(t)

	mock.ExpectQuery("SELECT (.|\n)*FROM incident_actions").
		WithArgs("inc-1").
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "incident_id", "action_type", "operator_id", "verifier_id",
			"description", "evidence", "marshal_decision", "worm_entry_id", "created_at",
		}))

	actions, err := store.ListActions(context.Background(), "inc-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if actions == nil {
		t.Error("expected ListActions to return an empty slice, not nil, when there are no rows")
	}
}
