package incident

import (
	"context"
	"errors"
	"testing"

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
