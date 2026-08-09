package mentions_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/mentions"
)

func newBadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestNotifyMentions_UnresolvableUsers_ReturnsNilWithoutPanic verifies that
// NotifyMentions skips usernames it cannot resolve (DB error here) rather
// than propagating the lookup failure — mentions of nonexistent/misspelled
// usernames must not break the calling request.
func TestNotifyMentions_UnresolvableUsers_ReturnsNilWithoutPanic(t *testing.T) {
	pool := newBadPool(t)

	err := mentions.NotifyMentions(context.Background(), pool, "actor-1", []string{"alice", "bob"}, "post-1", "comment-1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

// TestNotifyMentions_EmptyMentionList_ReturnsNil verifies the trivial no-op
// case: no mentioned usernames means no DB interaction is required, so a
// nil pool must not cause a panic.
func TestNotifyMentions_EmptyMentionList_ReturnsNil(t *testing.T) {
	err := mentions.NotifyMentions(context.Background(), nil, "actor-1", nil, "", "")
	if err != nil {
		t.Fatalf("expected nil error for empty mention list, got %v", err)
	}
}
