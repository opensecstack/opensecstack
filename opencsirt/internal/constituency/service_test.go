package constituency

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

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
