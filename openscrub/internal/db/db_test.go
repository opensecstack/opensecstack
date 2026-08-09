package db

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/opensecstack/openscrub/internal/rules"
)

// TestDBPingNilSafe covers the (*DB)(nil) and Pool==nil guard in Ping —
// exercised in production when a caller constructs Deps before New()
// succeeds (e.g. DB configured but unreachable at startup).
func TestDBPingNilSafe(t *testing.T) {
	var d *DB
	if err := d.Ping(context.Background()); err == nil {
		t.Fatal("expected error pinging a nil *DB")
	}

	d = &DB{}
	if err := d.Ping(context.Background()); err == nil {
		t.Fatal("expected error pinging a DB with a nil Pool")
	}
}

// TestDBCloseNilSafe ensures Close never panics on a nil receiver or a
// DB with no pool — both are reachable during startup-failure cleanup.
func TestDBCloseNilSafe(t *testing.T) {
	var d *DB
	d.Close() // must not panic

	d = &DB{}
	d.Close() // must not panic
}

// TestErrRuleNotFoundWrapsRulesErrNotFound guards the errors.Is
// contract the service layer depends on: db.ErrRuleNotFound must
// unwrap to rules.ErrNotFound so callers can check for either.
func TestErrRuleNotFoundWrapsRulesErrNotFound(t *testing.T) {
	if !errors.Is(ErrRuleNotFound, rules.ErrNotFound) {
		t.Fatal("ErrRuleNotFound does not wrap rules.ErrNotFound")
	}
}

func TestNullableUUID(t *testing.T) {
	if got := nullableUUID(uuid.NullUUID{Valid: false}); got != nil {
		t.Fatalf("invalid NullUUID: got %v, want nil", got)
	}
	id := uuid.New()
	got := nullableUUID(uuid.NullUUID{UUID: id, Valid: true})
	gotUUID, ok := got.(uuid.UUID)
	if !ok || gotUUID != id {
		t.Fatalf("valid NullUUID: got %v (ok=%v), want %v", got, ok, id)
	}
}

func TestNullableText(t *testing.T) {
	if got := nullableText(""); got != nil {
		t.Fatalf("empty string: got %v, want nil", got)
	}
	if got := nullableText("hello"); got != "hello" {
		t.Fatalf("non-empty string: got %v, want %q", got, "hello")
	}
}
