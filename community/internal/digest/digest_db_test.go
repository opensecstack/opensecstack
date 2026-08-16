package digest_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/db"
	"github.com/opensecstack/community/internal/digest"
	"github.com/opensecstack/community/internal/email"
)

// defaultTestDBURL mirrors the convention established in
// internal/db/audit_test.go and internal/api/handlers/oauth_testutil_internal_test.go.
const defaultTestDBURL = "postgres://apiguard@localhost:5434/community_test?sslmode=disable"

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("COMMUNITY_TEST_DB_URL")
	if url == "" {
		url = defaultTestDBURL
	}
	pool, err := db.Connect(url, 5)
	if err != nil {
		t.Skipf("real test DB unavailable, skipping DB-backed test: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return pool
}

func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// createUser inserts a user row and returns its id, cleaning it up (and
// anything that cascades from it) at the end of the test.
func createUser(t *testing.T, pool *pgxpool.Pool, username, emailAddr string, emailVerified bool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO users (username, email, email_verified) VALUES ($1, $2, $3) RETURNING id`,
		username, emailAddr, emailVerified,
	).Scan(&id)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

func createPublishedPost(t *testing.T, pool *pgxpool.Pool, authorID, title, slug string, publishedAt time.Time) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO posts (author_id, title, slug, body, state, published_at)
		VALUES ($1, $2, $3, 'hello world', 'published', $4) RETURNING id`,
		authorID, title, slug, publishedAt,
	).Scan(&id)
	if err != nil {
		t.Fatalf("create test post: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM posts WHERE id = $1`, id)
	})
	return id
}

// TestRun_HappyPath_SendsToOptedInUserAndUpdatesLastDigestAt exercises the
// full success path: a published post from the last 7 days exists, and one
// eligible recipient (email verified, digest_enabled = true) exists. Run
// must send the digest (via the log-only fallback since no SMTP host is
// configured) and stamp last_digest_at on the recipient.
func TestRun_HappyPath_SendsToOptedInUserAndUpdatesLastDigestAt(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	authorID := createUser(t, pool, "digest-author-"+suffix, "author-"+suffix+"@example.com", true)
	createPublishedPost(t, pool, authorID, "Top Post "+suffix, "top-post-"+suffix, time.Now().Add(-time.Hour))

	recipientID := createUser(t, pool, "digest-recipient-"+suffix, "recipient-"+suffix+"@example.com", true)
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_preferences (user_id, digest_enabled) VALUES ($1, true)`, recipientID,
	); err != nil {
		t.Fatalf("insert notification_preferences: %v", err)
	}

	cfg := &config.Config{DigestEnabled: true, SiteURL: "https://sin.to"}
	mailer := email.New(email.Config{SiteURL: "https://sin.to"}) // no Host -> log-only, no real SMTP needed

	if err := digest.Run(ctx, pool, mailer, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var lastDigestAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_digest_at FROM users WHERE id = $1`, recipientID).Scan(&lastDigestAt); err != nil {
		t.Fatalf("select last_digest_at: %v", err)
	}
	if lastDigestAt == nil {
		t.Fatal("expected last_digest_at to be set after a successful digest send")
	}
}

// TestRun_UserWithoutPreferencesRow_ExcludedByDefault verifies that a user
// with no notification_preferences row at all is not sent a digest (the
// INNER JOIN in Run's recipient query excludes them, matching the "digest
// defaults to false" comment in digest.go) and does not get last_digest_at
// touched.
func TestRun_UserWithoutPreferencesRow_ExcludedByDefault(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	authorID := createUser(t, pool, "digest-author2-"+suffix, "author2-"+suffix+"@example.com", true)
	createPublishedPost(t, pool, authorID, "Another Post "+suffix, "another-post-"+suffix, time.Now().Add(-time.Hour))

	noPrefsUserID := createUser(t, pool, "digest-noprefs-"+suffix, "noprefs-"+suffix+"@example.com", true)

	cfg := &config.Config{DigestEnabled: true, SiteURL: "https://sin.to"}
	mailer := email.New(email.Config{SiteURL: "https://sin.to"})

	if err := digest.Run(ctx, pool, mailer, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var lastDigestAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_digest_at FROM users WHERE id = $1`, noPrefsUserID).Scan(&lastDigestAt); err != nil {
		t.Fatalf("select last_digest_at: %v", err)
	}
	if lastDigestAt != nil {
		t.Fatal("expected last_digest_at to remain unset for a user with no notification_preferences row")
	}
}

// TestRun_NoPublishedPostsInWindow_SkipsWithoutTouchingUsersTable verifies
// the "nothing to send" early return (digest.go's `if len(posts) == 0`) —
// even an eligible recipient must not be touched when there is nothing to
// send them.
func TestRun_NoPublishedPostsInWindow_SkipsWithoutTouchingUsersTable(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	authorID := createUser(t, pool, "digest-author3-"+suffix, "author3-"+suffix+"@example.com", true)
	// Published far outside the 7-day window, so it must not be picked up.
	createPublishedPost(t, pool, authorID, "Stale Post "+suffix, "stale-post-"+suffix, time.Now().Add(-30*24*time.Hour))

	recipientID := createUser(t, pool, "digest-recipient3-"+suffix, "recipient3-"+suffix+"@example.com", true)
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_preferences (user_id, digest_enabled) VALUES ($1, true)`, recipientID,
	); err != nil {
		t.Fatalf("insert notification_preferences: %v", err)
	}

	cfg := &config.Config{DigestEnabled: true, SiteURL: "https://sin.to"}
	mailer := email.New(email.Config{SiteURL: "https://sin.to"})

	if err := digest.Run(ctx, pool, mailer, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var lastDigestAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_digest_at FROM users WHERE id = $1`, recipientID).Scan(&lastDigestAt); err != nil {
		t.Fatalf("select last_digest_at: %v", err)
	}
	if lastDigestAt != nil {
		t.Fatal("expected last_digest_at to remain unset when there are no posts to send")
	}
}
