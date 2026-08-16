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

// TestUpsertTags_Success_CreatesLinksAndReplacesOnSecondCall exercises the
// live-DB success path: new tags get created and linked, slugs are
// normalized, and a second call with a different tag set fully replaces the
// links for the post (DELETE-then-reinsert semantics).
func TestUpsertTags_Success_CreatesLinksAndReplacesOnSecondCall(t *testing.T) {
	pool := NewTestDBPool(t)
	d := Deps{Pool: pool}

	username := "upsert_" + RandomSuffix()
	var authorID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username) VALUES ($1) RETURNING id`, username,
	).Scan(&authorID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	CleanupUserByUsername(t, pool, username)

	postSlug := "upsertpost-" + RandomSuffix()
	var postID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO posts (author_id, title, slug, body) VALUES ($1,'T',$2,'b') RETURNING id`,
		authorID, postSlug,
	).Scan(&postID); err != nil {
		t.Fatalf("insert post: %v", err)
	}

	suffix := RandomSuffix()
	tagA := "Go " + suffix
	tagB := "Security " + suffix
	if err := upsertTags(context.Background(), d, postID, []string{tagA, tagB, "  "}); err != nil {
		t.Fatalf("upsertTags: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tags WHERE slug LIKE $1`, "%"+suffix+"%")
	})

	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM post_tags WHERE post_id=$1`, postID,
	).Scan(&count); err != nil {
		t.Fatalf("query post_tags: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 linked tags (blank name skipped), got %d", count)
	}

	// Second call with a single, different tag must replace the previous links.
	tagC := "Rust " + suffix
	if err := upsertTags(context.Background(), d, postID, []string{tagC}); err != nil {
		t.Fatalf("upsertTags (second call): %v", err)
	}

	var count2 int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM post_tags WHERE post_id=$1`, postID,
	).Scan(&count2); err != nil {
		t.Fatalf("query post_tags after replace: %v", err)
	}
	if count2 != 1 {
		t.Fatalf("expected exactly 1 linked tag after replace, got %d", count2)
	}
}
