package advisory

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

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
