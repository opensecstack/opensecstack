package rules

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestServiceGetReturnsRule(t *testing.T) {
	svc, _, _, _ := newSvc(t)
	created, err := svc.Create(context.Background(), CreateRequest{
		Type: TypeBlocklist, CIDR: "203.0.113.0/24", TTLSeconds: 60,
	}, "tester", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != created.ID || got.CIDR != created.CIDR {
		t.Fatalf("Get returned %+v, want match for %+v", got, created)
	}
}

func TestServiceGetUnknownReturnsErrNotFound(t *testing.T) {
	svc, _, _, _ := newSvc(t)
	_, err := svc.Get(context.Background(), uuid.New())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryRepoCount(t *testing.T) {
	repo := NewMemoryRepo()
	ctx := context.Background()
	n, err := repo.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("Count() = %d on empty repo, want 0", n)
	}
	if _, err := repo.Insert(ctx, Rule{Type: TypeBlocklist, CIDR: "10.0.0.0/8", TTLSeconds: 60, Source: SourceOperator}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Insert(ctx, Rule{Type: TypeBlocklist, CIDR: "10.1.0.0/16", TTLSeconds: 60, Source: SourceOperator}); err != nil {
		t.Fatal(err)
	}
	n, err = repo.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("Count() = %d after 2 inserts, want 2", n)
	}
}

func TestCIDRToAddr(t *testing.T) {
	addr, err := CIDRToAddr("203.0.113.42/24")
	if err != nil {
		t.Fatalf("CIDRToAddr: %v", err)
	}
	// ParseCIDR masks to the network address; /24 of .42 -> .0.
	if addr.String() != "203.0.113.0" {
		t.Fatalf("CIDRToAddr masked addr = %q, want 203.0.113.0", addr.String())
	}
}

func TestCIDRToAddrInvalid(t *testing.T) {
	if _, err := CIDRToAddr("not-a-cidr"); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

// TestNoopLifecycleMethodsAreSafeNoOps guards the dev-mode default: all
// three methods must be callable with zero values and never panic,
// since NoopLifecycle is used whenever no DB/store is configured.
func TestNoopLifecycleMethodsAreSafeNoOps(t *testing.T) {
	var lc NoopLifecycle
	ctx := context.Background()
	lc.OnRuleCreated(ctx, Rule{ID: uuid.New()})
	lc.OnRuleDeleted(ctx, Rule{ID: uuid.New()})
	lc.RecoverActive(ctx, []Rule{{ID: uuid.New()}})
	// No assertions beyond "did not panic" — by design these are no-ops.
}
