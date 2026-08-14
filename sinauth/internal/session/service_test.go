//go:build integration

package session

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestService_CreateGetRevoke exercises the Service wrapper end-to-end
// (Create -> Get -> Revoke -> Get fails), proving it delegates correctly
// to the Store rather than, e.g., swallowing errors or losing fields.
func TestService_CreateGetRevoke(t *testing.T) {
	pool := requireDB(t)
	store := NewStore(pool)
	svc := NewService(store)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("svcuser%d", time.Now().UnixNano()))

	sess, err := svc.Create(ctx, userID, "svcuser", time.Hour)
	if err != nil {
		t.Fatalf("Service.Create: %v", err)
	}
	if sess.UserID != userID || sess.Username != "svcuser" {
		t.Fatalf("Service.Create returned %+v, want user=%s username=svcuser", sess, userID)
	}

	got, err := svc.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Service.Get: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("Service.Get id = %q, want %q", got.ID, sess.ID)
	}

	if err := svc.Revoke(ctx, sess.ID); err != nil {
		t.Fatalf("Service.Revoke: %v", err)
	}

	if _, err := svc.Get(ctx, sess.ID); err == nil {
		t.Fatal("Service.Get after Revoke = nil error, want an error")
	}
}

// TestService_ListAllAndListByUsername proves the Service list methods
// delegate correctly and remain user-scoped where expected.
func TestService_ListAllAndListByUsername(t *testing.T) {
	pool := requireDB(t)
	store := NewStore(pool)
	svc := NewService(store)
	ctx := context.Background()

	uname := fmt.Sprintf("svclistuser%d", time.Now().UnixNano())
	userID := createTestUser(t, pool, uname)

	sess, err := svc.Create(ctx, userID, uname, time.Hour)
	if err != nil {
		t.Fatalf("Service.Create: %v", err)
	}
	t.Cleanup(func() { _ = svc.Revoke(ctx, sess.ID) })

	all, err := svc.ListAll(ctx)
	if err != nil {
		t.Fatalf("Service.ListAll: %v", err)
	}
	var foundAll bool
	for _, s := range all {
		if s.ID == sess.ID {
			foundAll = true
		}
	}
	if !foundAll {
		t.Fatalf("Service.ListAll missing created session %s", sess.ID)
	}

	byUser, err := svc.ListByUsername(ctx, uname)
	if err != nil {
		t.Fatalf("Service.ListByUsername: %v", err)
	}
	if len(byUser) != 1 || byUser[0].ID != sess.ID {
		t.Fatalf("Service.ListByUsername(%q) = %+v, want exactly the one session %s", uname, byUser, sess.ID)
	}
}
