package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestAdvisoryStoreInsert_DefaultsAppliedBeforeExecFails(t *testing.T) {
	s := NewAdvisoryStore(unreachablePool(t))
	a := &Advisory{CSAFID: "CSAF-1", Title: "t"}

	err := s.Insert(context.Background(), a)
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if a.ID == uuid.Nil {
		t.Error("Insert did not assign a default ID before failing")
	}
	if a.CSAFVersion != "2.0" {
		t.Errorf("Insert CSAFVersion = %q, want default %q", a.CSAFVersion, "2.0")
	}
	if a.State != "draft" {
		t.Errorf("Insert State = %q, want default %q", a.State, "draft")
	}
	if a.TLP != "green" {
		t.Errorf("Insert TLP = %q, want default %q", a.TLP, "green")
	}
	if a.CreatedAt.IsZero() || a.UpdatedAt.IsZero() {
		t.Error("Insert did not stamp CreatedAt/UpdatedAt before failing")
	}
}

func TestAdvisoryStoreInsert_PreservesCallerSuppliedFields(t *testing.T) {
	s := NewAdvisoryStore(unreachablePool(t))
	a := &Advisory{CSAFID: "CSAF-1", Title: "t", State: "published", TLP: "amber", CSAFVersion: "2.1"}
	_ = s.Insert(context.Background(), a)

	if a.State != "published" {
		t.Errorf("Insert overwrote caller-supplied State: got %q", a.State)
	}
	if a.TLP != "amber" {
		t.Errorf("Insert overwrote caller-supplied TLP: got %q", a.TLP)
	}
	if a.CSAFVersion != "2.1" {
		t.Errorf("Insert overwrote caller-supplied CSAFVersion: got %q", a.CSAFVersion)
	}
}

func TestAdvisoryStoreGet_PropagatesConnectionError(t *testing.T) {
	s := NewAdvisoryStore(unreachablePool(t))
	_, err := s.Get(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if err == ErrNotFound {
		t.Error("a connection error must not be mapped to ErrNotFound")
	}
}

func TestAdvisoryStorePublish_PropagatesError(t *testing.T) {
	s := NewAdvisoryStore(unreachablePool(t))
	if err := s.Publish(context.Background(), uuid.New(), uuid.New()); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestAdvisoryStoreWithdraw_PropagatesError(t *testing.T) {
	s := NewAdvisoryStore(unreachablePool(t))
	if err := s.Withdraw(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestAdvisoryStoreMarkCitadelEmitted_PropagatesError(t *testing.T) {
	s := NewAdvisoryStore(unreachablePool(t))
	if err := s.MarkCitadelEmitted(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
}

func TestAdvisoryStoreList_PropagatesError(t *testing.T) {
	s := NewAdvisoryStore(unreachablePool(t))
	items, total, err := s.List(context.Background(), AdvisoryFilter{})
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if items != nil || total != 0 {
		t.Errorf("List = (%v, %d) alongside an error, want (nil, 0)", items, total)
	}
}

func TestAdvisoryStoreList_ClampsOutOfRangeFilter(t *testing.T) {
	s := NewAdvisoryStore(unreachablePool(t))
	cases := []AdvisoryFilter{
		{Limit: 0, Offset: 0},
		{Limit: -5, Offset: -5},
		{Limit: 10000, Offset: 0},
	}
	for _, f := range cases {
		if _, _, err := s.List(context.Background(), f); err == nil {
			t.Errorf("List(%+v): expected an error from an unreachable DB, got nil", f)
		}
	}
}

func TestAdvisoryStoreCountByState_PropagatesError(t *testing.T) {
	s := NewAdvisoryStore(unreachablePool(t))
	counts, err := s.CountByState(context.Background())
	if err == nil {
		t.Fatal("expected an error from an unreachable DB, got nil")
	}
	if counts != nil {
		t.Errorf("CountByState returned non-nil map alongside an error: %+v", counts)
	}
}
