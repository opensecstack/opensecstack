package correlate

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
)

// TestCorrelateIOC_NilEngineReturnsZeroNoPanic proves CorrelateIOC is safe to
// call through a nil *Engine — handlers hold this pointer optionally.
func TestCorrelateIOC_NilEngineReturnsZeroNoPanic(t *testing.T) {
	var e *Engine
	n, err := e.CorrelateIOC(context.Background(), &store.IOC{ID: uuid.New(), Type: "ipv4-addr"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
}

// TestCorrelateIOC_NilCorrelationStoreReturnsZero proves the "correlation
// disabled" contract: an Engine built without a correlation store must not
// attempt any query (which would nil-pointer panic on e.corr) and must
// return (0, nil) cleanly.
func TestCorrelateIOC_NilCorrelationStoreReturnsZero(t *testing.T) {
	e := New(nil, nil, zerolog.Nop())
	n, err := e.CorrelateIOC(context.Background(), &store.IOC{ID: uuid.New(), Type: "domain-name", Value: "evil.example"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
}

func TestNew_WiresFields(t *testing.T) {
	e := New(nil, nil, zerolog.Nop())
	if e == nil {
		t.Fatal("New returned nil")
	}
	if e.corr != nil {
		t.Error("expected nil corr store to be preserved as-is")
	}
}
