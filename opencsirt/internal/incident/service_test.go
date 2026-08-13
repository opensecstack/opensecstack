package incident

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/db"
)

// unreachablePool returns a pgx pool configured against a syntactically
// valid but unreachable address. pgxpool.NewWithConfig never dials
// eagerly, so construction always succeeds; the first real query then
// fails fast with a connection error. This exercises Create/Get/List/
// Close/UpdateStatus's real store calls and error-propagation branches —
// previously entirely uncovered — without a live Postgres and without
// mocking db.IncidentStore/OutboxStore/AuditStore, which have no
// interface seam.
func unreachablePool(t *testing.T) *db.Pool {
	t.Helper()
	pool, err := db.Open(context.Background(), "postgres://user:pass@127.0.0.1:1/db", 1)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func newTestService(t *testing.T) *Service {
	pool := unreachablePool(t)
	return New(db.NewIncidentStore(pool), db.NewOutboxStore(pool), db.NewAuditStore(pool), zerolog.Nop())
}

func TestNewReturnsUsableService(t *testing.T) {
	s := New(nil, nil, nil, zerolog.Nop())
	if s == nil {
		t.Fatal("New returned nil")
	}
}

// Create must validate source/severity/title before ever touching the
// incidents store — verified with a nil store: a panic would mean
// validation was bypassed.
func TestServiceCreate_InvalidSourceNeverTouchesStore(t *testing.T) {
	s := New(nil, nil, nil, zerolog.Nop())
	_, err := s.Create(context.Background(), CreateInput{
		Source: "not-a-source", Severity: "high", Title: "t",
	}, uuid.New(), "admin")
	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("got %v want ErrInvalidSource", err)
	}
}

func TestServiceCreate_InvalidSeverityNeverTouchesStore(t *testing.T) {
	s := New(nil, nil, nil, zerolog.Nop())
	_, err := s.Create(context.Background(), CreateInput{
		Source: "manual", Severity: "apocalyptic", Title: "t",
	}, uuid.New(), "admin")
	if !errors.Is(err, ErrInvalidSeverity) {
		t.Fatalf("got %v want ErrInvalidSeverity", err)
	}
}

func TestServiceCreate_EmptyTitleNeverTouchesStore(t *testing.T) {
	s := New(nil, nil, nil, zerolog.Nop())
	_, err := s.Create(context.Background(), CreateInput{
		Source: "manual", Severity: "high", Title: "   ",
	}, uuid.New(), "admin")
	if !errors.Is(err, ErrEmptyTitle) {
		t.Fatalf("got %v want ErrEmptyTitle", err)
	}
}

func TestServiceCreate_ValidSourcesAccepted(t *testing.T) {
	// Only validate the source/severity/title gate passes for every
	// documented valid source; each must get past validation (i.e. fail
	// later, at the nil store, rather than on ErrInvalidSource).
	for _, src := range []string{"irflow", "manual", "abuse_mailbox", "peer_csirt"} {
		t.Run(src, func(t *testing.T) {
			s := New(nil, nil, nil, zerolog.Nop())
			defer func() {
				// A nil-store panic here is expected and PROVES validation
				// passed; ErrInvalidSource would not panic.
				if r := recover(); r == nil {
					t.Fatalf("expected panic reaching nil store for valid source %q (validation should have passed)", src)
				}
			}()
			_, _ = s.Create(context.Background(), CreateInput{
				Source: src, Severity: "low", Title: "t",
			}, uuid.New(), "admin")
		})
	}
}

func TestServiceUpdateStatus_InvalidStatusNeverTouchesStore(t *testing.T) {
	s := New(nil, nil, nil, zerolog.Nop())
	err := s.UpdateStatus(context.Background(), uuid.New(), "not-a-status", uuid.New(), "admin")
	if !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("got %v want ErrInvalidStatus", err)
	}
}

func TestServiceUpdateStatus_ValidStatusesPassValidation(t *testing.T) {
	for _, status := range []string{"open", "triaged", "contained", "closed"} {
		t.Run(status, func(t *testing.T) {
			s := New(nil, nil, nil, zerolog.Nop())
			defer func() {
				// A nil-store panic here PROVES the status passed
				// validation and UpdateStatus moved on to s.incidents.Get.
				if r := recover(); r == nil {
					t.Fatalf("expected panic reaching nil store for valid status %q", status)
				}
			}()
			_ = s.UpdateStatus(context.Background(), uuid.New(), status, uuid.New(), "admin")
		})
	}
}

// TestServiceCreate_StoreErrorPropagates exercises the real (previously
// 0%-covered) path past validation: valid input reaches store.Insert,
// which fails against an unreachable DB; that error must reach the
// caller, and the outbox enqueue / audit insert that follow a successful
// insert must not run (both would panic against the real-but-unreachable
// pool only if actually attempted with a nonexistent incident, so this
// primarily proves Create returns promptly on the Insert error instead of
// pressing on).
func TestServiceCreate_StoreErrorPropagates(t *testing.T) {
	s := newTestService(t)
	inc, err := s.Create(context.Background(), CreateInput{
		Source: "manual", Severity: "high", Title: "Test incident",
	}, uuid.New(), "operator")
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
	if inc != nil {
		t.Errorf("Create returned a non-nil incident alongside an error: %+v", inc)
	}
}

// TestServiceGet_StoreErrorPropagates proves Get is a thin, faithful
// pass-through to the store.
func TestServiceGet_StoreErrorPropagates(t *testing.T) {
	s := newTestService(t)
	if _, err := s.Get(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
}

// TestServiceList_StoreErrorPropagates proves List faithfully propagates
// the store error/total.
func TestServiceList_StoreErrorPropagates(t *testing.T) {
	s := newTestService(t)
	items, total, err := s.List(context.Background(), db.IncidentFilter{})
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
	if items != nil || total != 0 {
		t.Errorf("List = (%v, %d) alongside an error, want (nil, 0)", items, total)
	}
}

// TestServiceClose_GetErrorPropagates proves Close's first store call
// (Get, to check the current status) fails fast on an unreachable DB and
// never reaches UpdateStatus.
func TestServiceClose_GetErrorPropagates(t *testing.T) {
	s := newTestService(t)
	inc, err := s.Close(context.Background(), uuid.New(), uuid.New(), "operator")
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
	if inc != nil {
		t.Errorf("Close returned a non-nil incident alongside an error: %+v", inc)
	}
}

// TestServiceUpdateStatus_GetErrorPropagates proves UpdateStatus's
// idempotency-guard read (store.Get) fails fast on an unreachable DB and
// never reaches the UPDATE statement.
func TestServiceUpdateStatus_GetErrorPropagates(t *testing.T) {
	s := newTestService(t)
	err := s.UpdateStatus(context.Background(), uuid.New(), "triaged", uuid.New(), "operator")
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
}

// ── fake store seams ────────────────────────────────────────────────
//
// Service depends on the unexported incidentStore/outboxStore/auditStore
// interfaces (see service.go); *db.IncidentStore/*db.OutboxStore/
// *db.AuditStore satisfy them implicitly. These fakes let tests drive the
// success path and partial-failure branches (e.g. store succeeds but
// outbox/audit fails) deterministically without a live Postgres.

type fakeIncidentStore struct {
	insertErr error
	getErr    error
	getResult *db.Incident
	updateErr error
	listErr   error
	listItems []*db.Incident
	listTotal int

	updateCalls []struct {
		status   string
		closedAt *time.Time
	}
}

func (f *fakeIncidentStore) Insert(_ context.Context, i *db.Incident) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	i.ID = uuid.New()
	return nil
}

func (f *fakeIncidentStore) Get(_ context.Context, _ uuid.UUID) (*db.Incident, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getResult != nil {
		cp := *f.getResult
		return &cp, nil
	}
	return &db.Incident{ID: uuid.New(), Status: "open"}, nil
}

func (f *fakeIncidentStore) UpdateStatus(_ context.Context, _ uuid.UUID, status string, closedAt *time.Time) error {
	f.updateCalls = append(f.updateCalls, struct {
		status   string
		closedAt *time.Time
	}{status, closedAt})
	if f.updateErr != nil {
		return f.updateErr
	}
	return nil
}

func (f *fakeIncidentStore) List(_ context.Context, _ db.IncidentFilter) ([]*db.Incident, int, error) {
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.listItems, f.listTotal, nil
}

type fakeOutboxStore struct {
	enqueueErr error
	entries    []*db.OutboxEntry
}

func (f *fakeOutboxStore) Enqueue(_ context.Context, e *db.OutboxEntry) error {
	f.entries = append(f.entries, e)
	if f.enqueueErr != nil {
		return f.enqueueErr
	}
	return nil
}

type fakeAuditStore struct {
	insertErr error
	inserted  []*db.AuditEntry
}

func (f *fakeAuditStore) Insert(_ context.Context, a *db.AuditEntry) error {
	f.inserted = append(f.inserted, a)
	if f.insertErr != nil {
		return f.insertErr
	}
	return nil
}

var errBoom = errors.New("boom")

func newFakeService() (*Service, *fakeIncidentStore, *fakeOutboxStore, *fakeAuditStore) {
	inc := &fakeIncidentStore{}
	out := &fakeOutboxStore{}
	aud := &fakeAuditStore{}
	s := New(nil, nil, nil, zerolog.Nop())
	s.incidents, s.outbox, s.audit = inc, out, aud
	return s, inc, out, aud
}

// TestServiceCreate_SuccessEnqueuesOutboxAndAudits exercises Create's full
// happy path: validation passes, the store insert succeeds, an
// incident.opened outbox event is enqueued, and an audit entry is
// recorded.
func TestServiceCreate_SuccessEnqueuesOutboxAndAudits(t *testing.T) {
	s, _, out, aud := newFakeService()

	actor := uuid.New()
	inc, err := s.Create(context.Background(), CreateInput{
		Source: "manual", Severity: "high", Title: "  Test  ",
	}, actor, "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inc == nil || inc.ID == uuid.Nil {
		t.Fatal("expected an incident with an assigned ID")
	}
	if inc.Title != "Test" {
		t.Errorf("Title = %q, want trimmed 'Test'", inc.Title)
	}
	if inc.Status != "open" {
		t.Errorf("Status = %q, want open", inc.Status)
	}
	if len(out.entries) != 1 {
		t.Fatalf("expected one outbox entry, got %d", len(out.entries))
	}
	if len(aud.inserted) != 1 || aud.inserted[0].Action != "incident.create" {
		t.Fatalf("expected one incident.create audit entry, got %+v", aud.inserted)
	}
}

// TestServiceCreate_OutboxAndAuditFailuresAreSwallowed proves that
// failures in the outbox enqueue and audit insert (both best-effort,
// post-commit side effects) are logged, not propagated — the caller still
// gets back the created incident.
func TestServiceCreate_OutboxAndAuditFailuresAreSwallowed(t *testing.T) {
	s, _, out, aud := newFakeService()
	out.enqueueErr = errBoom
	aud.insertErr = errBoom

	inc, err := s.Create(context.Background(), CreateInput{
		Source: "manual", Severity: "high", Title: "Test",
	}, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("expected Create to succeed despite outbox/audit failures, got %v", err)
	}
	if inc == nil {
		t.Fatal("expected non-nil incident despite outbox/audit failures")
	}
}

// TestServiceClose_SuccessUpdatesEnqueuesAndAudits exercises Close's full
// happy path: Get finds a non-closed incident, UpdateStatus succeeds, a
// incident.closed outbox event is enqueued, and an audit entry recorded.
func TestServiceClose_SuccessUpdatesEnqueuesAndAudits(t *testing.T) {
	s, inc, out, aud := newFakeService()
	inc.getResult = &db.Incident{ID: uuid.New(), Status: "open"}

	got, err := s.Close(context.Background(), inc.getResult.ID, uuid.New(), "operator")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != "closed" {
		t.Errorf("Status = %q, want closed", got.Status)
	}
	if got.ClosedAt == nil {
		t.Error("expected ClosedAt to be set")
	}
	if len(inc.updateCalls) != 1 || inc.updateCalls[0].status != "closed" {
		t.Fatalf("expected one UpdateStatus(closed) call, got %+v", inc.updateCalls)
	}
	if len(out.entries) != 1 {
		t.Fatalf("expected one outbox entry, got %d", len(out.entries))
	}
	if len(aud.inserted) != 1 || aud.inserted[0].Action != "incident.close" {
		t.Fatalf("expected one incident.close audit entry, got %+v", aud.inserted)
	}
}

// TestServiceClose_AlreadyClosedReturnsErrorWithoutUpdating proves Close
// short-circuits on an already-closed incident without calling
// UpdateStatus, enqueueing an outbox event, or writing an audit entry.
func TestServiceClose_AlreadyClosedReturnsErrorWithoutUpdating(t *testing.T) {
	s, inc, out, aud := newFakeService()
	inc.getResult = &db.Incident{ID: uuid.New(), Status: "closed"}

	got, err := s.Close(context.Background(), inc.getResult.ID, uuid.New(), "operator")
	if !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("got %v want ErrAlreadyClosed", err)
	}
	if got != nil {
		t.Errorf("expected nil incident, got %+v", got)
	}
	if len(inc.updateCalls) != 0 {
		t.Errorf("expected no UpdateStatus call, got %+v", inc.updateCalls)
	}
	if len(out.entries) != 0 {
		t.Errorf("expected no outbox entry, got %+v", out.entries)
	}
	if len(aud.inserted) != 0 {
		t.Errorf("expected no audit entry, got %+v", aud.inserted)
	}
}

// TestServiceClose_UpdateStatusErrorPropagatesAndSkipsFollowup proves that
// when the UpdateStatus store call fails after a successful Get, the error
// reaches the caller and neither the outbox enqueue nor the audit insert
// are attempted.
func TestServiceClose_UpdateStatusErrorPropagatesAndSkipsFollowup(t *testing.T) {
	s, inc, out, aud := newFakeService()
	inc.getResult = &db.Incident{ID: uuid.New(), Status: "open"}
	inc.updateErr = errBoom

	got, err := s.Close(context.Background(), inc.getResult.ID, uuid.New(), "operator")
	if !errors.Is(err, errBoom) {
		t.Fatalf("got %v want errBoom", err)
	}
	if got != nil {
		t.Errorf("expected nil incident, got %+v", got)
	}
	if len(out.entries) != 0 {
		t.Errorf("expected no outbox entry when UpdateStatus fails, got %+v", out.entries)
	}
	if len(aud.inserted) != 0 {
		t.Errorf("expected no audit entry when UpdateStatus fails, got %+v", aud.inserted)
	}
}

// TestServiceUpdateStatus_IdempotentNoopSkipsStoreWriteAndSideEffects
// proves the H3 idempotency guard: when the incident is already in the
// target status, UpdateStatus returns nil without calling the store's
// UpdateStatus, enqueueing an escalation event, or writing an audit entry.
func TestServiceUpdateStatus_IdempotentNoopSkipsStoreWriteAndSideEffects(t *testing.T) {
	s, inc, out, aud := newFakeService()
	inc.getResult = &db.Incident{ID: uuid.New(), Status: "triaged"}

	err := s.UpdateStatus(context.Background(), inc.getResult.ID, "triaged", uuid.New(), "operator")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inc.updateCalls) != 0 {
		t.Errorf("expected no UpdateStatus store call for idempotent no-op, got %+v", inc.updateCalls)
	}
	if len(out.entries) != 0 {
		t.Errorf("expected no outbox entry for idempotent no-op, got %+v", out.entries)
	}
	if len(aud.inserted) != 0 {
		t.Errorf("expected no audit entry for idempotent no-op, got %+v", aud.inserted)
	}
}

// TestServiceUpdateStatus_TriagedEnqueuesEscalationAndAudits proves the
// real transition path: status differs, the store update runs, the
// "triaged" transition additionally enqueues an escalation outbox event,
// and an audit entry is recorded.
func TestServiceUpdateStatus_TriagedEnqueuesEscalationAndAudits(t *testing.T) {
	s, inc, out, aud := newFakeService()
	inc.getResult = &db.Incident{ID: uuid.New(), Status: "open"}

	err := s.UpdateStatus(context.Background(), inc.getResult.ID, "triaged", uuid.New(), "operator")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inc.updateCalls) != 1 || inc.updateCalls[0].status != "triaged" {
		t.Fatalf("expected one UpdateStatus(triaged) call, got %+v", inc.updateCalls)
	}
	if len(out.entries) != 1 {
		t.Fatalf("expected one escalation outbox entry, got %d", len(out.entries))
	}
	if len(aud.inserted) != 1 || aud.inserted[0].Action != "incident.update_status" {
		t.Fatalf("expected one incident.update_status audit entry, got %+v", aud.inserted)
	}
}

// TestServiceUpdateStatus_NonTriagedTransitionDoesNotEnqueueEscalation
// proves the escalation outbox event is only enqueued for the "triaged"
// transition, not for other valid status changes.
func TestServiceUpdateStatus_NonTriagedTransitionDoesNotEnqueueEscalation(t *testing.T) {
	s, inc, out, aud := newFakeService()
	inc.getResult = &db.Incident{ID: uuid.New(), Status: "triaged"}

	err := s.UpdateStatus(context.Background(), inc.getResult.ID, "contained", uuid.New(), "operator")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.entries) != 0 {
		t.Errorf("expected no escalation outbox entry for non-triaged transition, got %+v", out.entries)
	}
	if len(aud.inserted) != 1 {
		t.Fatalf("expected one audit entry regardless, got %+v", aud.inserted)
	}
}

// TestServiceUpdateStatus_StoreUpdateErrorPropagatesAndSkipsFollowup
// proves that when the store's UpdateStatus call fails after a successful
// Get, the error reaches the caller and neither the escalation outbox
// enqueue nor the audit insert are attempted.
func TestServiceUpdateStatus_StoreUpdateErrorPropagatesAndSkipsFollowup(t *testing.T) {
	s, inc, out, aud := newFakeService()
	inc.getResult = &db.Incident{ID: uuid.New(), Status: "open"}
	inc.updateErr = errBoom

	err := s.UpdateStatus(context.Background(), inc.getResult.ID, "triaged", uuid.New(), "operator")
	if !errors.Is(err, errBoom) {
		t.Fatalf("got %v want errBoom", err)
	}
	if len(out.entries) != 0 {
		t.Errorf("expected no outbox entry when store update fails, got %+v", out.entries)
	}
	if len(aud.inserted) != 0 {
		t.Errorf("expected no audit entry when store update fails, got %+v", aud.inserted)
	}
}

// TestServiceList_SuccessPassesThrough proves List returns exactly what
// the store returns on success.
func TestServiceList_SuccessPassesThrough(t *testing.T) {
	s, inc, _, _ := newFakeService()
	want := []*db.Incident{{ID: uuid.New(), Title: "Acme"}}
	inc.listItems = want
	inc.listTotal = 1

	got, total, err := s.List(context.Background(), db.IncidentFilter{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].Title != "Acme" {
		t.Errorf("List = (%+v, %d), want ([Acme], 1)", got, total)
	}
}

// TestServiceGet_SuccessPassesThrough proves Get is a faithful
// pass-through on the success path too, not just on error.
func TestServiceGet_SuccessPassesThrough(t *testing.T) {
	s, inc, _, _ := newFakeService()
	want := &db.Incident{ID: uuid.New(), Title: "Acme"}
	inc.getResult = want

	got, err := s.Get(context.Background(), want.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Title != "Acme" {
		t.Errorf("Get = %+v, want Title=Acme", got)
	}
}

func TestErrorsAreDistinctSentinels(t *testing.T) {
	errs := []error{ErrInvalidSource, ErrInvalidSeverity, ErrInvalidStatus, ErrEmptyTitle, ErrAlreadyClosed}
	for i, e1 := range errs {
		for j, e2 := range errs {
			if i != j && errors.Is(e1, e2) {
				t.Errorf("errors at index %d and %d should be distinct: %v vs %v", i, j, e1, e2)
			}
		}
	}
}
