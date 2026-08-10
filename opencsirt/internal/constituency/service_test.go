package constituency

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
// fails fast with a connection error. This lets Service.Create/Update/
// Get/List be exercised past validation into their real store calls (the
// happy path needs a live Postgres and is covered by the integration
// suite; this covers the error-propagation branches that were previously
// entirely uncovered) without mocking db.ConstituencyStore, which has no
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

func TestValidateRejectsBadEmail(t *testing.T) {
	err := validate(CreateInput{
		Name: "Acme", Sector: "energy", Country: "AL",
		NIS2Status: "essential", PrimaryContactEmail: "not-an-email",
	})
	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("got %v want ErrInvalidEmail", err)
	}
}

func TestValidateRejectsBadNIS2Status(t *testing.T) {
	err := validate(CreateInput{
		Name: "Acme", Sector: "energy", Country: "AL",
		NIS2Status: "vital", PrimaryContactEmail: "ops@acme.al",
	})
	if !errors.Is(err, ErrInvalidNIS2Status) {
		t.Fatalf("got %v want ErrInvalidNIS2Status", err)
	}
}

func TestValidateAcceptsValidInput(t *testing.T) {
	err := validate(CreateInput{
		Name: "Acme", Sector: "energy", Country: "AL",
		NIS2Status: "essential", PrimaryContactEmail: "ops@acme.al",
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestValidateRejectsEmptyFields(t *testing.T) {
	err := validate(CreateInput{
		Name: "", Sector: "energy", Country: "AL",
		NIS2Status: "essential", PrimaryContactEmail: "ops@acme.al",
	})
	if !errors.Is(err, ErrEmptyField) {
		t.Fatalf("got %v want ErrEmptyField", err)
	}
}

func TestValidateRejectsBadTLP(t *testing.T) {
	err := validate(CreateInput{
		Name: "Acme", Sector: "energy", Country: "AL",
		NIS2Status: "essential", TLPDefault: "black",
	})
	if !errors.Is(err, ErrInvalidTLP) {
		t.Fatalf("got %v want ErrInvalidTLP", err)
	}
}

func TestValidateAcceptsEmptyTLPDefaultsToGreen(t *testing.T) {
	err := validate(CreateInput{
		Name: "Acme", Sector: "energy", Country: "AL",
		NIS2Status: "essential", TLPDefault: "",
	})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestValidateRejectsBadSecondaryEmail(t *testing.T) {
	err := validate(CreateInput{
		Name: "Acme", Sector: "energy", Country: "AL",
		NIS2Status: "essential", PrimaryContactEmail: "ops@acme.al",
		SecondaryContactEmail: "not-an-email",
	})
	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("got %v want ErrInvalidEmail", err)
	}
}

func TestValidateRejectsEmptySector(t *testing.T) {
	err := validate(CreateInput{
		Name: "Acme", Sector: "  ", Country: "AL",
		NIS2Status: "essential",
	})
	if !errors.Is(err, ErrEmptyField) {
		t.Fatalf("got %v want ErrEmptyField", err)
	}
}

func TestOptionalTrimsAndConvertsEmptyToNil(t *testing.T) {
	if got := optional("  "); got != nil {
		t.Fatalf("optional(whitespace) = %v, want nil", got)
	}
	if got := optional(""); got != nil {
		t.Fatalf("optional(\"\") = %v, want nil", got)
	}
	got := optional("  foo@bar.com  ")
	if got == nil || *got != "foo@bar.com" {
		t.Fatalf("optional trimmed = %v, want foo@bar.com", got)
	}
}

func TestNewReturnsUsableService(t *testing.T) {
	s := New(nil, nil, zerolog.Nop())
	if s == nil {
		t.Fatal("New returned nil")
	}
}

// Create/Update must reject invalid input before ever touching the store —
// verified here by passing a nil store: a panic would mean validation was
// bypassed and the code fell through to a nil-pointer dereference.
func TestServiceCreate_InvalidInputNeverTouchesStore(t *testing.T) {
	s := New(nil, nil, zerolog.Nop())
	_, err := s.Create(context.Background(), CreateInput{
		Name: "", Sector: "energy", NIS2Status: "essential",
	}, uuid.New(), "admin")
	if !errors.Is(err, ErrEmptyField) {
		t.Fatalf("got %v want ErrEmptyField", err)
	}
}

func TestServiceUpdate_InvalidInputNeverTouchesStore(t *testing.T) {
	s := New(nil, nil, zerolog.Nop())
	_, err := s.Update(context.Background(), uuid.New(), CreateInput{
		Name: "Acme", Sector: "energy", NIS2Status: "not-a-status",
	}, uuid.New(), "admin")
	if !errors.Is(err, ErrInvalidNIS2Status) {
		t.Fatalf("got %v want ErrInvalidNIS2Status", err)
	}
}

// TestServiceCreate_StoreErrorPropagates exercises the real (previously
// 0%-covered) path past validation: valid input reaches store.Insert, the
// insert fails against an unreachable DB, and that error — not a
// swallowed/wrapped/nil substitute — must come back to the caller. It also
// proves Create does not panic or otherwise mishandle the audit-store call
// when the main store call already failed (the audit Insert call is
// correctly skipped on the early return).
func TestServiceCreate_StoreErrorPropagates(t *testing.T) {
	pool := unreachablePool(t)
	s := New(db.NewConstituencyStore(pool), db.NewAuditStore(pool), zerolog.Nop())
	c, err := s.Create(context.Background(), CreateInput{
		Name: "Acme", Sector: "energy", Country: "AL",
		NIS2Status: "essential", PrimaryContactEmail: "ops@acme.al",
	}, uuid.New(), "admin")
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
	if c != nil {
		t.Errorf("Create returned a non-nil constituency alongside an error: %+v", c)
	}
}

// TestServiceUpdate_GetErrorPropagates exercises Update's first store call
// (store.Get) failing — the update SQL must never run in that case.
func TestServiceUpdate_GetErrorPropagates(t *testing.T) {
	pool := unreachablePool(t)
	s := New(db.NewConstituencyStore(pool), db.NewAuditStore(pool), zerolog.Nop())
	c, err := s.Update(context.Background(), uuid.New(), CreateInput{
		Name: "Acme", Sector: "energy", NIS2Status: "essential",
	}, uuid.New(), "admin")
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
	if c != nil {
		t.Errorf("Update returned a non-nil constituency alongside an error: %+v", c)
	}
}

// TestServiceGet_StoreErrorPropagates proves Get is a thin, faithful
// pass-through to the store: the error from an unreachable DB must reach
// the caller unmodified/unswallowed. (The store's convention — like
// IncidentStore.Get and IOCIngestStore.LastForSource — is to also return a
// pre-allocated, zero-value struct pointer alongside the error; that's
// fine because every caller, including the HTTP handler, checks err before
// touching the result.)
func TestServiceGet_StoreErrorPropagates(t *testing.T) {
	pool := unreachablePool(t)
	s := New(db.NewConstituencyStore(pool), db.NewAuditStore(pool), zerolog.Nop())
	if _, err := s.Get(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
}

// TestServiceList_StoreErrorPropagates proves List faithfully propagates
// the store error and count, rather than e.g. returning a false total on
// error.
func TestServiceList_StoreErrorPropagates(t *testing.T) {
	pool := unreachablePool(t)
	s := New(db.NewConstituencyStore(pool), db.NewAuditStore(pool), zerolog.Nop())
	items, total, err := s.List(context.Background(), 10, 0)
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
	if items != nil {
		t.Errorf("List returned non-nil items alongside an error: %+v", items)
	}
	if total != 0 {
		t.Errorf("List returned total=%d alongside an error, want 0", total)
	}
}
