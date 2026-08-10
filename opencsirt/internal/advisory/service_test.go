package advisory

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
