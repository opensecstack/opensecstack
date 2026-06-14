package constituency

import (
	"errors"
	"testing"
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
