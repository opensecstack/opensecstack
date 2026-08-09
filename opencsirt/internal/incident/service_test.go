package incident

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

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
