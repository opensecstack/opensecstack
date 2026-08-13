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

// ── fake store seams ────────────────────────────────────────────────
//
// Service depends on the unexported constituencyStore/auditStore
// interfaces (see service.go); *db.ConstituencyStore/*db.AuditStore
// satisfy them implicitly. These fakes let tests drive the success path
// and partial-failure branches (e.g. store succeeds but audit fails)
// deterministically without a live Postgres.

type fakeConstituencyStore struct {
	insertErr error
	getErr    error
	getResult *db.Constituency
	updateErr error
	listErr   error
	listItems []*db.Constituency
	listTotal int

	inserted *db.Constituency
	updated  *db.Constituency
}

func (f *fakeConstituencyStore) Insert(_ context.Context, c *db.Constituency) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	c.ID = uuid.New()
	f.inserted = c
	return nil
}

func (f *fakeConstituencyStore) Get(_ context.Context, _ uuid.UUID) (*db.Constituency, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getResult != nil {
		cp := *f.getResult
		return &cp, nil
	}
	return &db.Constituency{ID: uuid.New()}, nil
}

func (f *fakeConstituencyStore) Update(_ context.Context, c *db.Constituency) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.updated = c
	return nil
}

func (f *fakeConstituencyStore) List(_ context.Context, _, _ int) ([]*db.Constituency, int, error) {
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.listItems, f.listTotal, nil
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

// TestServiceCreate_SuccessInsertsAndAudits exercises the full happy path:
// validation passes, the store insert succeeds, and a matching audit entry
// is recorded.
func TestServiceCreate_SuccessInsertsAndAudits(t *testing.T) {
	store := &fakeConstituencyStore{}
	audit := &fakeAuditStore{}
	s := New(nil, nil, zerolog.Nop())
	s.store, s.audit = store, audit

	actor := uuid.New()
	c, err := s.Create(context.Background(), CreateInput{
		Name: "Acme", Sector: "energy", Country: "al",
		NIS2Status: "essential", PrimaryContactEmail: "ops@acme.al",
	}, actor, "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil || c.ID == uuid.Nil {
		t.Fatal("expected a constituency with an assigned ID")
	}
	if c.Country != "AL" {
		t.Errorf("Country = %q, want normalized uppercase AL", c.Country)
	}
	if c.TLPDefault != "green" {
		t.Errorf("TLPDefault = %q, want default green", c.TLPDefault)
	}
	if len(audit.inserted) != 1 || audit.inserted[0].Action != "constituency.create" {
		t.Fatalf("expected one constituency.create audit entry, got %+v", audit.inserted)
	}
	if *audit.inserted[0].ActorID != actor {
		t.Errorf("audit ActorID = %v, want %v", *audit.inserted[0].ActorID, actor)
	}
}

// TestServiceCreate_AuditFailureIsSwallowedButStoreResultReturned proves
// that an audit-insert failure after a successful store insert is logged,
// not propagated — the caller still gets back the created constituency.
func TestServiceCreate_AuditFailureIsSwallowedButStoreResultReturned(t *testing.T) {
	store := &fakeConstituencyStore{}
	audit := &fakeAuditStore{insertErr: errBoom}
	s := New(nil, nil, zerolog.Nop())
	s.store, s.audit = store, audit

	c, err := s.Create(context.Background(), CreateInput{
		Name: "Acme", Sector: "energy", NIS2Status: "essential",
	}, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("expected Create to succeed despite audit failure, got %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil constituency despite audit failure")
	}
}

// TestServiceUpdate_SuccessUpdatesAndAudits exercises Update's full happy
// path: Get succeeds, fields are overwritten from the input, Update
// succeeds, and an audit entry is recorded.
func TestServiceUpdate_SuccessUpdatesAndAudits(t *testing.T) {
	existing := &db.Constituency{ID: uuid.New(), Name: "Old", Sector: "old-sector"}
	store := &fakeConstituencyStore{getResult: existing}
	audit := &fakeAuditStore{}
	s := New(nil, nil, zerolog.Nop())
	s.store, s.audit = store, audit

	c, err := s.Update(context.Background(), existing.ID, CreateInput{
		Name: "New Name", Sector: "energy", Country: "al",
		NIS2Status: "important", TLPDefault: "amber",
	}, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Name != "New Name" || c.Sector != "energy" || c.Country != "AL" || c.TLPDefault != "amber" {
		t.Errorf("fields not updated as expected: %+v", c)
	}
	if store.updated == nil {
		t.Fatal("expected store.Update to have been called")
	}
	if len(audit.inserted) != 1 || audit.inserted[0].Action != "constituency.update" {
		t.Fatalf("expected one constituency.update audit entry, got %+v", audit.inserted)
	}
}

// TestServiceUpdate_UpdateStoreErrorPropagatesAndSkipsAudit proves that
// when store.Update fails after a successful Get, the error reaches the
// caller and the audit insert is never attempted.
func TestServiceUpdate_UpdateStoreErrorPropagatesAndSkipsAudit(t *testing.T) {
	store := &fakeConstituencyStore{getResult: &db.Constituency{ID: uuid.New()}, updateErr: errBoom}
	audit := &fakeAuditStore{}
	s := New(nil, nil, zerolog.Nop())
	s.store, s.audit = store, audit

	c, err := s.Update(context.Background(), uuid.New(), CreateInput{
		Name: "Acme", Sector: "energy", NIS2Status: "essential",
	}, uuid.New(), "admin")
	if !errors.Is(err, errBoom) {
		t.Fatalf("got %v want errBoom", err)
	}
	if c != nil {
		t.Errorf("Update returned non-nil constituency alongside an error: %+v", c)
	}
	if len(audit.inserted) != 0 {
		t.Errorf("expected no audit insert when store.Update fails, got %+v", audit.inserted)
	}
}

// TestServiceList_SuccessPassesThrough proves List returns exactly what
// the store returns on success.
func TestServiceList_SuccessPassesThrough(t *testing.T) {
	want := []*db.Constituency{{ID: uuid.New(), Name: "Acme"}}
	store := &fakeConstituencyStore{listItems: want, listTotal: 1}
	s := New(nil, nil, zerolog.Nop())
	s.store = store

	got, total, err := s.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].Name != "Acme" {
		t.Errorf("List = (%+v, %d), want ([Acme], 1)", got, total)
	}
}

// TestServiceGet_SuccessPassesThrough proves Get is a faithful pass-through
// on the success path too, not just on error.
func TestServiceGet_SuccessPassesThrough(t *testing.T) {
	want := &db.Constituency{ID: uuid.New(), Name: "Acme"}
	store := &fakeConstituencyStore{getResult: want}
	s := New(nil, nil, zerolog.Nop())
	s.store = store

	got, err := s.Get(context.Background(), want.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "Acme" {
		t.Errorf("Get = %+v, want Name=Acme", got)
	}
}
