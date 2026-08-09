package handlers

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func newBadPoolForTagsTest(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestUpsertTags_DBError_ReturnsError verifies upsertTags surfaces the
// DELETE failure rather than silently proceeding as if tags were cleared.
func TestUpsertTags_DBError_ReturnsError(t *testing.T) {
	pool := newBadPoolForTagsTest(t)
	d := Deps{Pool: pool}

	err := upsertTags(context.Background(), d, "post-1", []string{"go", "security"})
	if err == nil {
		t.Fatal("expected an error when the DELETE fails against an unreachable DB")
	}
}

// TestUpsertTags_EmptyTagNames_StillAttemptsDelete verifies the DELETE
// still runs even when tagNames is empty (clearing all tags is valid).
func TestUpsertTags_EmptyTagNames_StillAttemptsDelete(t *testing.T) {
	pool := newBadPoolForTagsTest(t)
	d := Deps{Pool: pool}

	err := upsertTags(context.Background(), d, "post-1", nil)
	if err == nil {
		t.Fatal("expected an error since the DELETE itself fails against an unreachable DB")
	}
}
