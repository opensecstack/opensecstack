package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestNewMarshalStore_ActionCount_DelegatesToDB confirms the marshal.Store
// adapter forwards ActionCount to the underlying *DB (and its error
// wrapping) rather than defining its own — a divergence here would mean
// AUGUR rule_02 sees different error behavior through the adapter than a
// direct *DB caller does.
func TestNewMarshalStore_ActionCount_DelegatesToDB(t *testing.T) {
	d := unreachableDB(t)
	store := NewMarshalStore(d)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, err := store.ActionCount(ctx, "user-1", time.Hour)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if count != 0 {
		t.Errorf("expected count=0 on error, got %d", count)
	}
	if !strings.Contains(err.Error(), "db: action count:") {
		t.Errorf("expected underlying db error to propagate through adapter, got: %v", err)
	}
}

// TestNewMarshalStore_AppendWORM_DelegatesToDB confirms the adapter forwards
// AppendWORM errors (rather than masking a failed append as success).
func TestNewMarshalStore_AppendWORM_DelegatesToDB(t *testing.T) {
	d := unreachableDB(t)
	store := NewMarshalStore(d)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	entry, err := store.AppendWORM(ctx, "src", "evt", "proj", []byte(`{}`), "", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if entry != nil {
		t.Errorf("expected nil entry on error, got %+v", entry)
	}
}

// TestNewMarshalStore_GetSigningKey_DelegatesToDB confirms the adapter
// forwards GetSigningKey errors distinctly from "key not found" — a real
// query failure must not silently look like exists=false to MARSHAL's
// signature gates through this adapter either (same guarantee as
// GetActiveKey itself, verified end-to-end through the adapter boundary).
func TestNewMarshalStore_GetSigningKey_DelegatesToDB(t *testing.T) {
	d := unreachableDB(t)
	store := NewMarshalStore(d)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pub, exists, err := store.GetSigningKey(ctx, "user-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if exists {
		t.Error("expected exists=false on error")
	}
	if pub != nil {
		t.Errorf("expected nil pubkey on error, got %v", pub)
	}
}
