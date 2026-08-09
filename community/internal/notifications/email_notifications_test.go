package notifications_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/notifications"
)

// fakeMailer records every SendHTML call so tests can assert whether (and
// what) was sent.
type fakeMailer struct {
	calls   int
	lastTo  string
	lastSub string
	err     error
}

func (f *fakeMailer) SendHTML(to, subject, body string) error {
	f.calls++
	f.lastTo = to
	f.lastSub = subject
	return f.err
}

func newBadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestSendFollowEmail_UnresolvableRecipient_SkipsSendSilently verifies that
// when the recipient's user row cannot be resolved (DB unreachable here,
// but the same code path as "user has no email set"), SendFollowEmail
// returns nil without ever calling the mailer — it must not attempt to
// deliver to an empty/unknown address.
func TestSendFollowEmail_UnresolvableRecipient_SkipsSendSilently(t *testing.T) {
	pool := newBadPool(t)
	mailer := &fakeMailer{}
	cfg := &config.Config{SiteURL: "https://sin.to"}

	err := notifications.SendFollowEmail(context.Background(), pool, mailer, cfg, "alice", "user-123")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if mailer.calls != 0 {
		t.Errorf("expected mailer.SendHTML to not be called, got %d calls", mailer.calls)
	}
}

func TestSendCommentEmail_UnresolvableRecipient_SkipsSendSilently(t *testing.T) {
	pool := newBadPool(t)
	mailer := &fakeMailer{}
	cfg := &config.Config{SiteURL: "https://sin.to"}

	err := notifications.SendCommentEmail(context.Background(), pool, mailer, cfg, "bob", "user-123", "my-post", "My Post", "nice post")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if mailer.calls != 0 {
		t.Errorf("expected mailer.SendHTML to not be called, got %d calls", mailer.calls)
	}
}

// TestSendReactionEmail_PreferenceQueryFails_DefaultsToNoSend verifies that,
// unlike follow/comment emails (which default the preference to "enabled"
// on a DB error), reaction emails default to NOT sending when the
// preference lookup fails — reactions are opt-in, so a lookup failure must
// fail closed, not open.
func TestSendReactionEmail_PreferenceQueryFails_DefaultsToNoSend(t *testing.T) {
	pool := newBadPool(t)
	mailer := &fakeMailer{}
	cfg := &config.Config{SiteURL: "https://sin.to"}

	err := notifications.SendReactionEmail(context.Background(), pool, mailer, cfg, "carol", "user-123", "my-post", "My Post", "heart")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if mailer.calls != 0 {
		t.Errorf("expected mailer.SendHTML to not be called when preference lookup fails, got %d calls", mailer.calls)
	}
}
