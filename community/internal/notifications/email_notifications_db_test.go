package notifications_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/db"
	"github.com/opensecstack/community/internal/notifications"
)

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

func createUser(t *testing.T, pool *pgxpool.Pool, username, emailAddr, displayName string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO users (username, email, display_name) VALUES ($1, $2, $3) RETURNING id`,
		username, emailAddr, displayName,
	).Scan(&id)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

// TestSendFollowEmail_OptedIn_SendsHTML verifies the full happy path: the
// recipient has email_follows enabled (and a resolvable email), so
// SendFollowEmail must actually call mailer.SendHTML with the follower's
// name baked into the subject/body.
func TestSendFollowEmail_OptedIn_SendsHTML(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	toID := createUser(t, pool, "follow-to-"+suffix, "follow-to-"+suffix+"@example.com", "")
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_preferences (user_id, email_follows) VALUES ($1, true)`, toID,
	); err != nil {
		t.Fatalf("insert notification_preferences: %v", err)
	}

	mailer := &fakeMailer{}
	cfg := &config.Config{SiteURL: "https://sin.to"}

	if err := notifications.SendFollowEmail(ctx, pool, mailer, cfg, "alice", toID); err != nil {
		t.Fatalf("SendFollowEmail: %v", err)
	}
	if mailer.calls != 1 {
		t.Fatalf("expected exactly 1 mailer.SendHTML call, got %d", mailer.calls)
	}
	if mailer.lastTo != "follow-to-"+suffix+"@example.com" {
		t.Errorf("unexpected recipient: %s", mailer.lastTo)
	}
}

// TestSendFollowEmail_OptedOut_DoesNotSend verifies the opt-out branch:
// email_follows = false must suppress the send entirely, even though the
// recipient is otherwise fully resolvable.
func TestSendFollowEmail_OptedOut_DoesNotSend(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	toID := createUser(t, pool, "follow-optout-"+suffix, "follow-optout-"+suffix+"@example.com", "")
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_preferences (user_id, email_follows) VALUES ($1, false)`, toID,
	); err != nil {
		t.Fatalf("insert notification_preferences: %v", err)
	}

	mailer := &fakeMailer{}
	cfg := &config.Config{SiteURL: "https://sin.to"}

	if err := notifications.SendFollowEmail(ctx, pool, mailer, cfg, "alice", toID); err != nil {
		t.Fatalf("SendFollowEmail: %v", err)
	}
	if mailer.calls != 0 {
		t.Fatalf("expected 0 mailer.SendHTML calls when opted out, got %d", mailer.calls)
	}
}

// TestSendCommentEmail_OptedIn_SendsHTML mirrors the follow-email happy
// path for comments.
func TestSendCommentEmail_OptedIn_SendsHTML(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	toID := createUser(t, pool, "comment-to-"+suffix, "comment-to-"+suffix+"@example.com", "Bob Author")
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_preferences (user_id, email_comments) VALUES ($1, true)`, toID,
	); err != nil {
		t.Fatalf("insert notification_preferences: %v", err)
	}

	mailer := &fakeMailer{}
	cfg := &config.Config{SiteURL: "https://sin.to"}

	if err := notifications.SendCommentEmail(ctx, pool, mailer, cfg, "carol", toID, "my-post", "My Post", "nice!"); err != nil {
		t.Fatalf("SendCommentEmail: %v", err)
	}
	if mailer.calls != 1 {
		t.Fatalf("expected exactly 1 mailer.SendHTML call, got %d", mailer.calls)
	}
}

// TestSendReactionEmail_OptedInAndNoRecentSend_SendsHTML verifies the
// reaction happy path: email_reactions = true and no notifications row
// created in the past 24h means the send must go through.
func TestSendReactionEmail_OptedInAndNoRecentSend_SendsHTML(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	toID := createUser(t, pool, "reaction-to-"+suffix, "reaction-to-"+suffix+"@example.com", "")
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_preferences (user_id, email_reactions) VALUES ($1, true)`, toID,
	); err != nil {
		t.Fatalf("insert notification_preferences: %v", err)
	}

	mailer := &fakeMailer{}
	cfg := &config.Config{SiteURL: "https://sin.to"}

	if err := notifications.SendReactionEmail(ctx, pool, mailer, cfg, "dave", toID, "my-post", "My Post", "heart"); err != nil {
		t.Fatalf("SendReactionEmail: %v", err)
	}
	if mailer.calls != 1 {
		t.Fatalf("expected exactly 1 mailer.SendHTML call, got %d", mailer.calls)
	}
}

// TestSendReactionEmail_OptedOut_DoesNotSend verifies the default-false
// opt-in semantics documented on SendReactionEmail: a preferences row with
// email_reactions explicitly false must suppress the send.
func TestSendReactionEmail_OptedOut_DoesNotSend(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	toID := createUser(t, pool, "reaction-optout-"+suffix, "reaction-optout-"+suffix+"@example.com", "")
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_preferences (user_id, email_reactions) VALUES ($1, false)`, toID,
	); err != nil {
		t.Fatalf("insert notification_preferences: %v", err)
	}

	mailer := &fakeMailer{}
	cfg := &config.Config{SiteURL: "https://sin.to"}

	if err := notifications.SendReactionEmail(ctx, pool, mailer, cfg, "dave", toID, "my-post", "My Post", "heart"); err != nil {
		t.Fatalf("SendReactionEmail: %v", err)
	}
	if mailer.calls != 0 {
		t.Fatalf("expected 0 mailer.SendHTML calls when opted out, got %d", mailer.calls)
	}
}

// TestSendReactionEmail_RecentDuplicateNotification_SuppressesSend verifies
// the 24h rate-limit: when more than one reaction_on_post notification for
// this user already exists within the last 24h, a further reaction email
// must be suppressed to avoid flooding the recipient's inbox.
func TestSendReactionEmail_RecentDuplicateNotification_SuppressesSend(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	toID := createUser(t, pool, "reaction-flood-"+suffix, "reaction-flood-"+suffix+"@example.com", "")
	if _, err := pool.Exec(ctx,
		`INSERT INTO notification_preferences (user_id, email_reactions) VALUES ($1, true)`, toID,
	); err != nil {
		t.Fatalf("insert notification_preferences: %v", err)
	}

	// SendReactionEmail suppresses when recentCount > 1, so seed two recent
	// reaction_on_post notification rows for this user (actor_id/post_id are
	// nullable-friendly except actor_id allows NULL; type check requires a
	// valid enum value).
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx, `
			INSERT INTO notifications (user_id, type, created_at) VALUES ($1, 'reaction_on_post', now())`,
			toID,
		); err != nil {
			t.Fatalf("seed notifications row %d: %v", i, err)
		}
	}

	mailer := &fakeMailer{}
	cfg := &config.Config{SiteURL: "https://sin.to"}

	if err := notifications.SendReactionEmail(ctx, pool, mailer, cfg, "dave", toID, "my-post", "My Post", "heart"); err != nil {
		t.Fatalf("SendReactionEmail: %v", err)
	}
	if mailer.calls != 0 {
		t.Fatalf("expected 0 mailer.SendHTML calls when rate-limited, got %d", mailer.calls)
	}
}

// TestSendFollowEmail_NoPreferencesRow_DefaultsToEnabled verifies the
// documented fail-open default for follows/comments: when no
// notification_preferences row exists at all, SendFollowEmail still sends
// (unlike reactions, which fail closed — see
// TestSendReactionEmail_PreferenceQueryFails_DefaultsToNoSend in the
// existing unreachable-DB test).
func TestSendFollowEmail_NoPreferencesRow_DefaultsToEnabled(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	toID := createUser(t, pool, "follow-nopref-"+suffix, "follow-nopref-"+suffix+"@example.com", "")
	// Deliberately no notification_preferences row.

	mailer := &fakeMailer{}
	cfg := &config.Config{SiteURL: "https://sin.to"}

	if err := notifications.SendFollowEmail(ctx, pool, mailer, cfg, "erin", toID); err != nil {
		t.Fatalf("SendFollowEmail: %v", err)
	}
	if mailer.calls != 1 {
		t.Fatalf("expected the follow email to send by default when no preferences row exists, got %d calls", mailer.calls)
	}
}
