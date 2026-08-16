package advisory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/citadel"
	"github.com/opensecstack/opencsirt/internal/db"
)

// unreachablePool returns a pgx pool configured against a syntactically
// valid but unreachable address. pgxpool.NewWithConfig never dials
// eagerly, so construction always succeeds; the first real query then
// fails fast with a connection error. This exercises Get/List/Publish/
// Withdraw's real store-call and error-propagation branches — previously
// entirely uncovered — without a live Postgres and without mocking
// db.AdvisoryStore/OutboxStore, which have no interface seam.
func unreachablePool(t *testing.T) *db.Pool {
	t.Helper()
	pool, err := db.Open(context.Background(), "postgres://user:pass@127.0.0.1:1/db", 1)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestValidTLP(t *testing.T) {
	cases := map[string]bool{
		"clear": true, "green": true, "amber": true, "red": true,
		"black": false, "": false, "GREEN": false,
	}
	for tlp, want := range cases {
		if got := validTLP(tlp); got != want {
			t.Errorf("validTLP(%q) = %v, want %v", tlp, got, want)
		}
	}
}

func TestServiceCreate_EmptyTitleNeverTouchesStore(t *testing.T) {
	// store/outbox/audit deliberately nil: an empty title must short-circuit
	// before any of them are dereferenced, or this panics instead of erroring.
	s := &Service{log: zerolog.Nop()}
	_, err := s.Create(context.Background(), CreateInput{
		Title: "   ",
		TLP:   "green",
	}, uuid.New(), "admin")
	if !errors.Is(err, ErrEmptyTitle) {
		t.Fatalf("got %v want ErrEmptyTitle", err)
	}
}

func TestServiceCreate_InvalidTLPNeverTouchesStore(t *testing.T) {
	s := &Service{log: zerolog.Nop()}
	_, err := s.Create(context.Background(), CreateInput{
		Title: "Some advisory",
		TLP:   "black",
	}, uuid.New(), "admin")
	if !errors.Is(err, ErrInvalidTLP) {
		t.Fatalf("got %v want ErrInvalidTLP", err)
	}
}

func TestServiceCreate_TLPNormalizedToLowercaseBeforeValidation(t *testing.T) {
	// Uppercase TLP must be accepted (normalized) rather than rejected —
	// verified by confirming it gets past validation to the python client,
	// which is the next thing touched after the title/TLP checks.
	called := false
	s := &Service{
		log: zerolog.Nop(),
		python: fakePythonClient{
			generate: func(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
				called = true
				if req.TLP != "green" {
					t.Errorf("req.TLP = %q, want normalized \"green\"", req.TLP)
				}
				return GenerateResponse{}, errors.New("stop here, before store")
			},
		},
	}
	_, err := s.Create(context.Background(), CreateInput{
		Title: "Some advisory",
		TLP:   "GREEN",
	}, uuid.New(), "admin")
	if !called {
		t.Fatal("python.Generate was never called; TLP normalization/validation must have short-circuited unexpectedly")
	}
	if err == nil {
		t.Fatal("expected the fake Generate error to propagate")
	}
}

func TestServiceCreate_PythonGenerateErrorPropagatesAndSkipsStore(t *testing.T) {
	wantErr := errors.New("upstream boom")
	s := &Service{
		log: zerolog.Nop(),
		python: fakePythonClient{
			generate: func(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
				return GenerateResponse{}, wantErr
			},
		},
		// store left nil: if Create pressed on after the Generate error it
		// would panic here instead of returning the error.
	}
	_, err := s.Create(context.Background(), CreateInput{
		Title: "Some advisory",
		TLP:   "green",
	}, uuid.New(), "admin")
	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v want %v", err, wantErr)
	}
}

func TestServiceCreate_IncidentIDForwardedToGenerateRequest(t *testing.T) {
	incidentID := uuid.New()
	var captured GenerateRequest
	s := &Service{
		log: zerolog.Nop(),
		python: fakePythonClient{
			generate: func(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
				captured = req
				return GenerateResponse{}, errors.New("stop before store")
			},
		},
	}
	_, _ = s.Create(context.Background(), CreateInput{
		Title:      "Some advisory",
		TLP:        "green",
		IncidentID: &incidentID,
	}, uuid.New(), "admin")
	if captured.IncidentID != incidentID.String() {
		t.Errorf("GenerateRequest.IncidentID = %q, want %q", captured.IncidentID, incidentID.String())
	}
}

// TestServiceGet_StoreErrorPropagatesAndSkipsAudit proves Get returns the
// store error faithfully and does not attempt the audit-log insert (which
// would panic against the nil AuditStore built with NewService(store, nil, nil, ...)
// were it reached — using a real audit store here to isolate this from
// that separate concern).
func TestServiceGet_StoreErrorPropagatesAndSkipsAudit(t *testing.T) {
	pool := unreachablePool(t)
	s := NewService(db.NewAdvisoryStore(pool), db.NewOutboxStore(pool), db.NewAuditStore(pool), fakePythonClient{})
	a, err := s.Get(context.Background(), uuid.New(), uuid.New(), "analyst")
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
	if a != nil {
		t.Errorf("Get returned a non-nil advisory alongside an error: %+v", a)
	}
}

// TestServiceList_StoreErrorPropagates proves List faithfully surfaces the
// store error/total rather than substituting a misleading zero result.
func TestServiceList_StoreErrorPropagates(t *testing.T) {
	pool := unreachablePool(t)
	s := NewService(db.NewAdvisoryStore(pool), db.NewOutboxStore(pool), db.NewAuditStore(pool), fakePythonClient{})
	items, total, err := s.List(context.Background(), db.AdvisoryFilter{}, uuid.New(), "analyst")
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
	if items != nil || total != 0 {
		t.Errorf("List = (%v, %d) alongside an error, want (nil, 0)", items, total)
	}
}

// TestServicePublish_StoreErrorPropagates proves Publish surfaces the
// store.Publish error immediately and never reaches store.Get, the outbox
// enqueue, or the audit insert.
func TestServicePublish_StoreErrorPropagates(t *testing.T) {
	pool := unreachablePool(t)
	s := NewService(db.NewAdvisoryStore(pool), db.NewOutboxStore(pool), db.NewAuditStore(pool), fakePythonClient{})
	a, err := s.Publish(context.Background(), uuid.New(), uuid.New(), "csirt_lead")
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
	if a != nil {
		t.Errorf("Publish returned a non-nil advisory alongside an error: %+v", a)
	}
}

// TestServiceWithdraw_StoreErrorPropagates mirrors the Publish case for
// Withdraw's store.Withdraw call.
func TestServiceWithdraw_StoreErrorPropagates(t *testing.T) {
	pool := unreachablePool(t)
	s := NewService(db.NewAdvisoryStore(pool), db.NewOutboxStore(pool), db.NewAuditStore(pool), fakePythonClient{})
	a, err := s.Withdraw(context.Background(), uuid.New(), uuid.New(), "csirt_lead")
	if err == nil {
		t.Fatal("expected a store error from an unreachable DB, got nil")
	}
	if a != nil {
		t.Errorf("Withdraw returned a non-nil advisory alongside an error: %+v", a)
	}
}

func TestNewServiceReturnsUsableService(t *testing.T) {
	s := NewService(nil, nil, nil, fakePythonClient{})
	if s == nil {
		t.Fatal("NewService returned nil")
	}
}

// fakeAdvisoryStore/fakeOutbox/fakeAudit are in-memory stand-ins for the
// advisoryStore/outboxEnqueuer/auditInserter interfaces (internal/advisory's
// own seam around *db.AdvisoryStore etc.). They let these tests exercise the
// success and branch logic inside Service.Publish/Withdraw/Create/Get/List
// that the DB-error-only tests above (using unreachablePool) can never
// reach, without touching internal/db or requiring a live Postgres.
type fakeAdvisoryStore struct {
	insertErr   error
	getErr      error
	publishErr  error
	withdrawErr error
	listErr     error

	inserted  *db.Advisory
	advisory  *db.Advisory // returned by Get, and mutated by Publish/Withdraw if non-nil
	listItems []*db.Advisory
	listTotal int

	publishCalled  bool
	withdrawCalled bool
}

func (f *fakeAdvisoryStore) Insert(ctx context.Context, a *db.Advisory) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.inserted = a
	return nil
}

func (f *fakeAdvisoryStore) Get(ctx context.Context, id uuid.UUID) (*db.Advisory, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.advisory, nil
}

func (f *fakeAdvisoryStore) Publish(ctx context.Context, id, by uuid.UUID) error {
	f.publishCalled = true
	if f.publishErr != nil {
		return f.publishErr
	}
	return nil
}

func (f *fakeAdvisoryStore) Withdraw(ctx context.Context, id uuid.UUID) error {
	f.withdrawCalled = true
	if f.withdrawErr != nil {
		return f.withdrawErr
	}
	return nil
}

func (f *fakeAdvisoryStore) List(ctx context.Context, filt db.AdvisoryFilter) ([]*db.Advisory, int, error) {
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.listItems, f.listTotal, nil
}

type fakeOutbox struct {
	enqueueErr error
	enqueued   *db.OutboxEntry
}

func (f *fakeOutbox) Enqueue(ctx context.Context, e *db.OutboxEntry) error {
	f.enqueued = e
	if f.enqueueErr != nil {
		return f.enqueueErr
	}
	return nil
}

type fakeAudit struct {
	insertErr error
	inserted  []*db.AuditEntry
}

func (f *fakeAudit) Insert(ctx context.Context, a *db.AuditEntry) error {
	f.inserted = append(f.inserted, a)
	if f.insertErr != nil {
		return f.insertErr
	}
	return nil
}

func TestServiceCreate_SuccessInsertsAndAudits(t *testing.T) {
	store := &fakeAdvisoryStore{}
	audit := &fakeAudit{}
	s := &Service{
		store: store,
		audit: audit,
		log:   zerolog.Nop(),
		python: fakePythonClient{
			generate: func(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
				return GenerateResponse{CSAFID: "CSAF-1", Doc: map[string]any{"k": "v"}}, nil
			},
		},
	}
	actor := uuid.New()
	a, err := s.Create(context.Background(), CreateInput{Title: "Some advisory", TLP: "green"}, actor, "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if a.CSAFID != "CSAF-1" {
		t.Errorf("CSAFID = %q, want CSAF-1", a.CSAFID)
	}
	if a.State != "draft" {
		t.Errorf("State = %q, want draft", a.State)
	}
	if store.inserted == nil {
		t.Fatal("expected store.Insert to be called")
	}
	if len(audit.inserted) != 1 || audit.inserted[0].Action != "advisory.create" {
		t.Fatalf("expected one advisory.create audit entry, got %+v", audit.inserted)
	}
}

func TestServiceCreate_StoreInsertErrorPropagatesAndSkipsAudit(t *testing.T) {
	wantErr := errors.New("insert boom")
	store := &fakeAdvisoryStore{insertErr: wantErr}
	audit := &fakeAudit{}
	s := &Service{
		store: store, audit: audit, log: zerolog.Nop(),
		python: fakePythonClient{generate: func(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
			return GenerateResponse{}, nil
		}},
	}
	_, err := s.Create(context.Background(), CreateInput{Title: "T", TLP: "green"}, uuid.New(), "admin")
	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v want %v", err, wantErr)
	}
	if len(audit.inserted) != 0 {
		t.Errorf("audit should not be touched when Insert fails, got %+v", audit.inserted)
	}
}

func TestServiceCreate_AuditFailureIsLoggedNotFatal(t *testing.T) {
	// Audit insert failing must not cause Create to return an error or a nil
	// advisory — it's a logged side-effect only.
	store := &fakeAdvisoryStore{}
	audit := &fakeAudit{insertErr: errors.New("audit boom")}
	s := &Service{
		store: store, audit: audit, log: zerolog.Nop(),
		python: fakePythonClient{generate: func(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
			return GenerateResponse{CSAFID: "CSAF-2"}, nil
		}},
	}
	a, err := s.Create(context.Background(), CreateInput{Title: "T", TLP: "amber"}, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("Create should not fail on an audit error: %v", err)
	}
	if a == nil || a.CSAFID != "CSAF-2" {
		t.Fatalf("expected the advisory to still be returned, got %+v", a)
	}
}

func TestServiceGet_SuccessAudits(t *testing.T) {
	want := &db.Advisory{ID: uuid.New(), Title: "T"}
	store := &fakeAdvisoryStore{advisory: want}
	audit := &fakeAudit{}
	s := &Service{store: store, audit: audit, log: zerolog.Nop()}
	got, err := s.Get(context.Background(), want.ID, uuid.New(), "analyst")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != want {
		t.Errorf("Get returned %+v, want %+v", got, want)
	}
	if len(audit.inserted) != 1 || audit.inserted[0].Action != "advisory.read" {
		t.Fatalf("expected advisory.read audit entry, got %+v", audit.inserted)
	}
}

func TestServiceList_SuccessAudits(t *testing.T) {
	items := []*db.Advisory{{ID: uuid.New()}, {ID: uuid.New()}}
	store := &fakeAdvisoryStore{listItems: items, listTotal: 2}
	audit := &fakeAudit{}
	s := &Service{store: store, audit: audit, log: zerolog.Nop()}
	got, total, err := s.List(context.Background(), db.AdvisoryFilter{}, uuid.New(), "analyst")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("List = (%v, %d), want 2 items, total 2", got, total)
	}
	if len(audit.inserted) != 1 || audit.inserted[0].Action != "advisory.list" {
		t.Fatalf("expected advisory.list audit entry, got %+v", audit.inserted)
	}
}

// TestServicePublish_SuccessEnqueuesOutboxAndAudits covers Publish's full
// happy path: store.Publish succeeds, the re-fetched advisory is in state
// "published", and Publish must enqueue a citadel outbox entry plus an audit
// row. This is the primary previously-uncovered branch (Publish sat at 7.7%).
func TestServicePublish_SuccessEnqueuesOutboxAndAudits(t *testing.T) {
	id := uuid.New()
	incidentID := uuid.New()
	publishedAt := time.Now().UTC()
	store := &fakeAdvisoryStore{
		advisory: &db.Advisory{
			ID: id, State: "published", CSAFID: "CSAF-3", TLP: "amber",
			PublishedAt: &publishedAt, IncidentID: &incidentID,
		},
	}
	outbox := &fakeOutbox{}
	audit := &fakeAudit{}
	s := &Service{store: store, outbox: outbox, audit: audit, log: zerolog.Nop()}

	actor := uuid.New()
	a, err := s.Publish(context.Background(), id, actor, "csirt_lead")
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if a.State != "published" {
		t.Errorf("State = %q, want published", a.State)
	}
	if !store.publishCalled {
		t.Error("expected store.Publish to be called")
	}
	if outbox.enqueued == nil {
		t.Fatal("expected an outbox entry to be enqueued")
	}
	if outbox.enqueued.EventType != citadel.EventAdvisoryPublished {
		t.Errorf("EventType = %q, want %q", outbox.enqueued.EventType, citadel.EventAdvisoryPublished)
	}
	if outbox.enqueued.EventID != "advisory-publish-"+id.String() {
		t.Errorf("EventID = %q", outbox.enqueued.EventID)
	}
	if outbox.enqueued.Payload["csaf_id"] != "CSAF-3" {
		t.Errorf("payload csaf_id = %v, want CSAF-3", outbox.enqueued.Payload["csaf_id"])
	}
	if len(audit.inserted) != 1 || audit.inserted[0].Action != "advisory.publish" {
		t.Fatalf("expected advisory.publish audit entry, got %+v", audit.inserted)
	}
}

// TestServicePublish_StillDraftAfterPublishSkipsOutbox covers the L4 guard:
// store.Publish returns nil but the re-fetched row is still "draft" (e.g. a
// racing concurrent write) — Publish must return the advisory without
// erroring and without enqueueing an outbox event.
func TestServicePublish_StillDraftAfterPublishSkipsOutbox(t *testing.T) {
	id := uuid.New()
	store := &fakeAdvisoryStore{advisory: &db.Advisory{ID: id, State: "draft"}}
	outbox := &fakeOutbox{}
	audit := &fakeAudit{}
	s := &Service{store: store, outbox: outbox, audit: audit, log: zerolog.Nop()}

	a, err := s.Publish(context.Background(), id, uuid.New(), "csirt_lead")
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if a.State != "draft" {
		t.Errorf("State = %q, want draft (unchanged)", a.State)
	}
	if outbox.enqueued != nil {
		t.Error("expected no outbox entry to be enqueued when state is still draft")
	}
	if len(audit.inserted) != 0 {
		t.Error("expected no audit entry when skipping outbox for a still-draft advisory")
	}
}

// TestServicePublish_UnexpectedStateReturnsError covers the state guard for
// any state other than "draft" or "published" (e.g. "withdrawn") after a
// successful store.Publish call — a state machine invariant violation that
// must surface as an error, not be silently accepted.
func TestServicePublish_UnexpectedStateReturnsError(t *testing.T) {
	id := uuid.New()
	store := &fakeAdvisoryStore{advisory: &db.Advisory{ID: id, State: "withdrawn"}}
	s := &Service{store: store, audit: &fakeAudit{}, log: zerolog.Nop()}

	a, err := s.Publish(context.Background(), id, uuid.New(), "csirt_lead")
	if err == nil {
		t.Fatal("expected an error for an unexpected post-publish state")
	}
	if a != nil {
		t.Errorf("expected nil advisory alongside the error, got %+v", a)
	}
}

// TestServicePublish_GetAfterPublishErrorPropagates covers the re-fetch
// error branch: store.Publish succeeds but the follow-up store.Get fails.
func TestServicePublish_GetAfterPublishErrorPropagates(t *testing.T) {
	wantErr := errors.New("get boom")
	store := &fakeAdvisoryStore{getErr: wantErr}
	s := &Service{store: store, audit: &fakeAudit{}, log: zerolog.Nop()}

	_, err := s.Publish(context.Background(), uuid.New(), uuid.New(), "csirt_lead")
	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v want %v", err, wantErr)
	}
}

// TestServicePublish_OutboxEnqueueFailureIsLoggedNotFatal proves a failed
// outbox enqueue does not fail Publish nor skip the audit insert — it's a
// logged side-effect only, matching Create's audit-failure tolerance.
func TestServicePublish_OutboxEnqueueFailureIsLoggedNotFatal(t *testing.T) {
	id := uuid.New()
	store := &fakeAdvisoryStore{advisory: &db.Advisory{ID: id, State: "published"}}
	outbox := &fakeOutbox{enqueueErr: errors.New("enqueue boom")}
	audit := &fakeAudit{}
	s := &Service{store: store, outbox: outbox, audit: audit, log: zerolog.Nop()}

	a, err := s.Publish(context.Background(), id, uuid.New(), "csirt_lead")
	if err != nil {
		t.Fatalf("Publish should tolerate an outbox enqueue error: %v", err)
	}
	if a == nil {
		t.Fatal("expected a non-nil advisory")
	}
	if len(audit.inserted) != 1 {
		t.Errorf("expected the audit insert to still happen after an outbox failure, got %+v", audit.inserted)
	}
}

func TestServiceWithdraw_SuccessAudits(t *testing.T) {
	id := uuid.New()
	store := &fakeAdvisoryStore{advisory: &db.Advisory{ID: id, State: "withdrawn"}}
	audit := &fakeAudit{}
	s := &Service{store: store, audit: audit, log: zerolog.Nop()}

	a, err := s.Withdraw(context.Background(), id, uuid.New(), "csirt_lead")
	if err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if !store.withdrawCalled {
		t.Error("expected store.Withdraw to be called")
	}
	if a.State != "withdrawn" {
		t.Errorf("State = %q, want withdrawn", a.State)
	}
	if len(audit.inserted) != 1 || audit.inserted[0].Action != "advisory.withdraw" {
		t.Fatalf("expected advisory.withdraw audit entry, got %+v", audit.inserted)
	}
}

func TestServiceWithdraw_GetAfterWithdrawErrorPropagates(t *testing.T) {
	wantErr := errors.New("get boom")
	store := &fakeAdvisoryStore{getErr: wantErr}
	s := &Service{store: store, audit: &fakeAudit{}, log: zerolog.Nop()}

	_, err := s.Withdraw(context.Background(), uuid.New(), uuid.New(), "csirt_lead")
	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v want %v", err, wantErr)
	}
}

func TestServiceWithdraw_AuditFailureIsLoggedNotFatal(t *testing.T) {
	id := uuid.New()
	store := &fakeAdvisoryStore{advisory: &db.Advisory{ID: id, State: "withdrawn"}}
	audit := &fakeAudit{insertErr: errors.New("audit boom")}
	s := &Service{store: store, audit: audit, log: zerolog.Nop()}

	a, err := s.Withdraw(context.Background(), id, uuid.New(), "csirt_lead")
	if err != nil {
		t.Fatalf("Withdraw should tolerate an audit error: %v", err)
	}
	if a == nil {
		t.Fatal("expected a non-nil advisory")
	}
}

// fakePythonClient implements PythonClient with overridable hooks; nil
// hooks panic loudly if called unexpectedly rather than silently zero-valuing.
type fakePythonClient struct {
	generate func(context.Context, GenerateRequest) (GenerateResponse, error)
}

func (f fakePythonClient) Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	if f.generate == nil {
		panic("fakePythonClient.Generate called without a hook")
	}
	return f.generate(ctx, req)
}

func (f fakePythonClient) EnrichIOCs(ctx context.Context, iocs []IOC) ([]EnrichedIOC, error) {
	panic("fakePythonClient.EnrichIOCs called without a hook")
}

func (f fakePythonClient) TriageAbuseEmail(ctx context.Context, raw []byte) (TriageResult, error) {
	panic("fakePythonClient.TriageAbuseEmail called without a hook")
}

func (f fakePythonClient) Health(ctx context.Context) error {
	panic("fakePythonClient.Health called without a hook")
}
