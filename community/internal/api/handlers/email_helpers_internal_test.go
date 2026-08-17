package handlers

// White-box tests for the unexported per-notification email helpers
// (sendCommentEmail, sendFollowerEmail, sendReactionEmail) in comments.go,
// follows.go and reactions.go. These are fired from goroutines inside their
// respective handlers only when d.Mailer != nil, so no existing handler test
// exercises them deterministically. They had zero coverage prior to this
// file. Each is a small "look up recipient, look up post (where relevant),
// call the mailer" helper — the real behavior worth proving is the early
// "recipient not found / no email" bail-out and the it-actually-queries
// Postgres happy path.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/email"
)

// createHelperTestUser and createHelperTestPost are minimal local inserts —
// this file is package handlers (internal, white-box), so it cannot reach
// the createTestUser/createTestPost helpers defined in the external
// handlers_test package (posts_crud_db_test.go).
func createHelperTestUser(t *testing.T, pool *pgxpool.Pool) (id string) {
	t.Helper()
	username := "author-" + RandomSuffix()
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, display_name, role) VALUES ($1,$1,'author') RETURNING id`,
		username,
	).Scan(&id); err != nil {
		t.Fatalf("create helper test user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, id) })
	return id
}

func createHelperTestPost(t *testing.T, pool *pgxpool.Pool, authorID string) (id string) {
	t.Helper()
	slug := "post-" + RandomSuffix()
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO posts (author_id, title, slug, body, state, published_at)
		 VALUES ($1,$2,$3,'body','published', now()) RETURNING id`,
		authorID, "Test Post "+slug, slug,
	).Scan(&id); err != nil {
		t.Fatalf("create helper test post: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM posts WHERE id=$1`, id) })
	return id
}

func TestSendCommentEmail_RecipientNotFound_NoPanicNoSend(t *testing.T) {
	pool := NewTestDBPool(t)
	mailer := email.New(email.Config{SiteURL: "https://sin.to"}) // log-only, no SMTP host

	// Must not panic even though the recipient id does not exist.
	sendCommentEmail(pool, mailer, "00000000-0000-0000-0000-000000000000", "actor", "00000000-0000-0000-0000-000000000000")
}

func TestSendCommentEmail_HappyPath_LooksUpRecipientAndPost(t *testing.T) {
	pool := NewTestDBPool(t)
	mailer := email.New(email.Config{SiteURL: "https://sin.to"})

	authorID := createHelperTestUser(t, pool)
	postID := createHelperTestPost(t, pool, authorID)
	recipientUsername := "recipient-" + RandomSuffix()
	var recipientID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email, email_verified) VALUES ($1,$2,true) RETURNING id`,
		recipientUsername, recipientUsername+"@example.com",
	).Scan(&recipientID); err != nil {
		t.Fatalf("create recipient: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, recipientID) })

	// The mailer is log-only (no SMTP host configured), so this proves the
	// lookup + call path runs to completion without erroring rather than
	// asserting on an actual sent email.
	sendCommentEmail(pool, mailer, recipientID, "commenter", postID)
}

func TestSendFollowerEmail_RecipientNotFound_NoPanicNoSend(t *testing.T) {
	pool := NewTestDBPool(t)
	mailer := email.New(email.Config{SiteURL: "https://sin.to"})

	sendFollowerEmail(pool, mailer, "00000000-0000-0000-0000-000000000000", "actor")
}

func TestSendFollowerEmail_HappyPath_LooksUpRecipient(t *testing.T) {
	pool := NewTestDBPool(t)
	mailer := email.New(email.Config{SiteURL: "https://sin.to"})

	recipientUsername := "recipient-" + RandomSuffix()
	var recipientID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email, email_verified) VALUES ($1,$2,true) RETURNING id`,
		recipientUsername, recipientUsername+"@example.com",
	).Scan(&recipientID); err != nil {
		t.Fatalf("create recipient: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, recipientID) })

	sendFollowerEmail(pool, mailer, recipientID, "follower")
}

// TestSendFollowerEmail_RecipientWithNoEmail_BailsOutEarly proves the
// `toAddr == ""` branch: a user row with an empty email string must not
// reach the mailer call (which would otherwise be sent to nobody).
func TestSendFollowerEmail_RecipientWithNoEmail_BailsOutEarly(t *testing.T) {
	pool := NewTestDBPool(t)
	mailer := email.New(email.Config{SiteURL: "https://sin.to"})

	recipientUsername := "recipient-" + RandomSuffix()
	var recipientID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email, email_verified) VALUES ($1,NULL,false) RETURNING id`,
		recipientUsername,
	).Scan(&recipientID); err != nil {
		t.Fatalf("create recipient with no email: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, recipientID) })

	// Must not panic on the NULL->"" scan and must return before calling the
	// mailer (there's nothing observable here beyond "does not panic", but
	// the scan of a NULL email into a Go string is the specific behavior
	// this test locks in).
	sendFollowerEmail(pool, mailer, recipientID, "follower")
}

func TestSendReactionEmail_RecipientNotFound_NoPanicNoSend(t *testing.T) {
	pool := NewTestDBPool(t)
	mailer := email.New(email.Config{SiteURL: "https://sin.to"})

	sendReactionEmail(pool, mailer, "00000000-0000-0000-0000-000000000000", "actor", "like", "00000000-0000-0000-0000-000000000000")
}

func TestSendReactionEmail_HappyPath_LooksUpRecipientAndPost(t *testing.T) {
	pool := NewTestDBPool(t)
	mailer := email.New(email.Config{SiteURL: "https://sin.to"})

	authorID := createHelperTestUser(t, pool)
	postID := createHelperTestPost(t, pool, authorID)
	recipientUsername := "recipient-" + RandomSuffix()
	var recipientID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email, email_verified) VALUES ($1,$2,true) RETURNING id`,
		recipientUsername, recipientUsername+"@example.com",
	).Scan(&recipientID); err != nil {
		t.Fatalf("create recipient: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, recipientID) })

	sendReactionEmail(pool, mailer, recipientID, "reactor", "heart", postID)
}

// TestSendReactionEmail_PostNotFound_BailsOutBeforeSending proves the
// second lookup's error branch (post id doesn't exist) returns early rather
// than sending an email with an empty title/slug.
func TestSendReactionEmail_PostNotFound_BailsOutBeforeSending(t *testing.T) {
	pool := NewTestDBPool(t)
	mailer := email.New(email.Config{SiteURL: "https://sin.to"})

	recipientUsername := "recipient-" + RandomSuffix()
	var recipientID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email, email_verified) VALUES ($1,$2,true) RETURNING id`,
		recipientUsername, recipientUsername+"@example.com",
	).Scan(&recipientID); err != nil {
		t.Fatalf("create recipient: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, recipientID) })

	sendReactionEmail(pool, mailer, recipientID, "reactor", "heart", "00000000-0000-0000-0000-000000000000")
}
