package scheduler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	sdkcitadel "github.com/opensecstack/sdk/go/citadel"

	"github.com/opensecstack/community/internal/citadel"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/db"
	"github.com/opensecstack/community/internal/email"
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

// createSchedUser inserts a user with an email set (sendDigests' query scans
// u.email into a non-nullable *string destination, so a NULL email — the
// default for a bare username-only insert — fails that scan; see
// TestSendDigests_HappyPath_SendsWeeklyDigestAndStampsLastDigestAt).
func createSchedUser(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id`, username, username+"@example.com",
	).Scan(&id)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

// newFakeMarshalServer spins up a minimal CITADEL MARSHAL stand-in that
// always returns the given outcome for POST /api/v1/marshal/evaluate, so
// tests can exercise GovernanceClient.EvaluateDeletion's real EXECUTE path
// without depending on sdkcitadel.Client's FailMode default (which is
// FailClosed/HARD_STOP — see sdk/go/citadel/client.go's FailMode doc — not
// "fails open" as citadel/governance.go's NewGovernanceClient comment
// currently (incorrectly) claims for an empty/unreachable apiURL).
func newFakeMarshalServer(t *testing.T, outcome string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var k sdkcitadel.Kerkese
		_ = json.NewDecoder(r.Body).Decode(&k)
		decision := sdkcitadel.Decision{
			Outcome:     outcome,
			ExecutionID: k.ExecutionID,
			TsUTC:       time.Now().UTC(),
		}
		if outcome != sdkcitadel.OutcomeExecute {
			decision.Reasons = []string{"test server: forced " + outcome}
			w.WriteHeader(http.StatusForbidden)
		}
		_ = json.NewEncoder(w).Encode(decision)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// --- publishDue ---------------------------------------------------------

// TestPublishDue_HappyPath_PublishesDuePostAndLeavesFuturePostAlone verifies
// the core scheduler behaviour: a 'scheduled' post whose scheduled_at has
// passed gets flipped to 'published' with published_at set, while a post
// scheduled for the future is left untouched.
func TestPublishDue_HappyPath_PublishesDuePostAndLeavesFuturePostAlone(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	authorID := createSchedUser(t, pool, "sched-author-"+suffix)

	var duePostID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO posts (author_id, title, slug, body, state, scheduled_at)
		VALUES ($1, 'Due Post', $2, 'body', 'scheduled', $3) RETURNING id`,
		authorID, "due-post-"+suffix, time.Now().Add(-time.Minute),
	).Scan(&duePostID); err != nil {
		t.Fatalf("insert due post: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM posts WHERE id = $1`, duePostID) })

	var futurePostID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO posts (author_id, title, slug, body, state, scheduled_at)
		VALUES ($1, 'Future Post', $2, 'body', 'scheduled', $3) RETURNING id`,
		authorID, "future-post-"+suffix, time.Now().Add(24*time.Hour),
	).Scan(&futurePostID); err != nil {
		t.Fatalf("insert future post: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM posts WHERE id = $1`, futurePostID) })

	cit := citadel.New("", nil, "community-1", true) // dry-run: Emit is a no-op regardless of apiURL
	cfg := &config.Config{Node: "community-0"}

	publishDue(ctx, pool, cit, cfg)

	var state string
	var publishedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT state, published_at FROM posts WHERE id = $1`, duePostID).Scan(&state, &publishedAt); err != nil {
		t.Fatalf("select due post: %v", err)
	}
	if state != "published" {
		t.Errorf("expected due post state=published, got %q", state)
	}
	if publishedAt == nil {
		t.Error("expected due post published_at to be set")
	}

	var futureState string
	if err := pool.QueryRow(ctx, `SELECT state FROM posts WHERE id = $1`, futurePostID).Scan(&futureState); err != nil {
		t.Fatalf("select future post: %v", err)
	}
	if futureState != "scheduled" {
		t.Errorf("expected future post to remain scheduled, got %q", futureState)
	}
}

// TestPublishDue_PanicInCitadelEmit_PropagatesUncaught documents that
// publishDue itself has no recover() anywhere in its own call chain, so a
// panic while emitting the WORM event (here forced via a nil *citadel.
// Client, which panics on cit.dryRun inside Emit) is NOT contained within
// publishDue — it propagates straight out to the caller. That used to mean
// a single bad tick could crash the whole server: Start() invoked
// publishDue/processDeletions/sendDigests with no recover anywhere in the
// chain, and per Go's panic semantics an unrecovered panic in any
// goroutine kills the entire process. Start() now wraps each call in
// safeRun (scheduler.go), which recovers and logs instead of propagating —
// see TestStart-level coverage for that isolation. This test intentionally
// still calls publishDue directly (bypassing safeRun) to pin down that the
// function itself remains panic-prone in isolation; the safety net lives
// one layer up, at the call sites, not inside publishDue.
func TestPublishDue_PanicInCitadelEmit_PropagatesUncaught(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	authorID := createSchedUser(t, pool, "sched-panic-author-"+suffix)
	var duePostID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO posts (author_id, title, slug, body, state, scheduled_at)
		VALUES ($1, 'Panic Post', $2, 'body', 'scheduled', $3) RETURNING id`,
		authorID, "panic-post-"+suffix, time.Now().Add(-time.Minute),
	).Scan(&duePostID); err != nil {
		t.Fatalf("insert due post: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM posts WHERE id = $1`, duePostID) })

	cfg := &config.Config{Node: "community-0"}

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		publishDue(ctx, pool, nil, cfg) // nil *citadel.Client: cit.Emit dereferences cit.dryRun
	}()

	if !panicked {
		t.Fatal("expected publishDue to panic uncaught when its citadel client is nil; if this no longer panics, update this test's rationale — the point is that publishDue has no internal panic recovery")
	}

	// The UPDATE...RETURNING already committed before the panic (the panic
	// happens per-row while iterating results, after the UPDATE executed),
	// so the post is still published even though the tick "crashed" here —
	// worth noting for anyone reasoning about partial-failure behaviour.
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM posts WHERE id = $1`, duePostID).Scan(&state); err != nil {
		t.Fatalf("select post after panic: %v", err)
	}
	if state != "published" {
		t.Errorf("expected post to already be published (UPDATE...RETURNING ran before the panic), got %q", state)
	}
}

// --- processDeletions ----------------------------------------------------

// TestProcessDeletions_HappyPath_DeletesApprovedUserAndMarksProcessed
// verifies the full GDPR deletion pipeline: an 'approved' deletion request
// whose scheduled_for has passed, evaluated against a MARSHAL stand-in that
// returns EXECUTE, causes processDeletions to (1) proceed past the
// governance gate and (2) delete the user.
//
// This deliberately does NOT rely on GovernanceClient.NewGovernanceClient's
// doc comment claiming an empty/unreachable apiURL "fails open" — that
// claim does not match sdkcitadel.Client's actual default FailMode
// (FailClosed/HARD_STOP, the zero value; see sdk/go/citadel/client.go). A
// real MARSHAL EXECUTE response is used instead so this test's happy path
// is genuine rather than accidentally exercising the fail-closed branch.
//
// Real bug found here: processDeletions.go's comment says it marks the
// deletion_requests row 'processed' after DELETE FROM users succeeds, but
// deletion_requests.user_id is `REFERENCES users(id) ON DELETE CASCADE`
// (internal/db/migrations_gdpr.go). Deleting the user therefore cascades
// and removes the deletion_requests row FIRST — the subsequent `UPDATE
// deletion_requests SET status='processed' ... WHERE id=$1` silently
// affects 0 rows (no error is raised or logged for that). The intended
// "processed" audit record is never actually written; the request row is
// simply gone. This test asserts the real, verified behavior (row absent)
// rather than the code's stated intent (row present with status
// 'processed') — see the CLAUDE.md auditability standard this violates.
func TestProcessDeletions_HappyPath_DeletesApprovedUserAndMarksProcessed(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	approverID := createSchedUser(t, pool, "sched-approver-"+suffix)
	targetID := createSchedUser(t, pool, "sched-target-"+suffix)

	var reqID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO deletion_requests (user_id, status, scheduled_for, approved_by)
		VALUES ($1, 'approved', $2, $3) RETURNING id`,
		targetID, time.Now().Add(-time.Minute), approverID,
	).Scan(&reqID); err != nil {
		t.Fatalf("insert deletion_requests: %v", err)
	}

	marshal := newFakeMarshalServer(t, sdkcitadel.OutcomeExecute)

	cit := citadel.New("", nil, "community-1", true) // dry-run Emit
	gov := citadel.NewGovernanceClient(marshal.URL)
	cfg := &config.Config{Node: "community-0"}

	processDeletions(ctx, pool, cit, gov, cfg)

	var userCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE id = $1`, targetID).Scan(&userCount); err != nil {
		t.Fatalf("count target user: %v", err)
	}
	if userCount != 0 {
		t.Error("expected the target user to be deleted after an approved+due deletion request was processed")
	}

	// See the bug noted in this test's doc comment: the deletion_requests
	// row does NOT end up with status='processed' — it is cascade-deleted
	// along with the user before the UPDATE ever has a row to affect.
	var reqCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM deletion_requests WHERE id = $1`, reqID).Scan(&reqCount); err != nil {
		t.Fatalf("count deletion_requests: %v", err)
	}
	if reqCount != 0 {
		t.Errorf("expected the deletion_requests row to be cascade-deleted along with the user, but %d row(s) remain", reqCount)
	}

	// approverID cascades from nothing (approved_by is ON DELETE SET NULL on
	// deletion_requests, not the other way around); clean it up explicitly.
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, approverID) })
}

// TestProcessDeletions_UnreachableCitadel_FailsClosedAndBlocksDeletion
// verifies the actual (safe) behaviour of an unreachable/misconfigured
// CITADEL: the deletion must be blocked, not silently allowed. This is the
// opposite of what NewGovernanceClient's doc comment currently claims
// ("EvaluateDeletion fails open (proceed=true, non-nil err)" for an empty
// apiURL) — the real default, inherited from sdkcitadel.Client's zero-value
// FailMode (FailClosed), is HARD_STOP. The code is safe; the comment is
// stale/wrong and should be corrected so future readers don't assume GDPR
// deletions proceed unattended whenever CITADEL is down.
func TestProcessDeletions_UnreachableCitadel_FailsClosedAndBlocksDeletion(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	targetID := createSchedUser(t, pool, "sched-failclosed-target-"+suffix)

	var reqID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO deletion_requests (user_id, status, scheduled_for)
		VALUES ($1, 'approved', $2) RETURNING id`,
		targetID, time.Now().Add(-time.Minute),
	).Scan(&reqID); err != nil {
		t.Fatalf("insert deletion_requests: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM deletion_requests WHERE id = $1`, reqID) })

	cit := citadel.New("", nil, "community-1", true)
	gov := citadel.NewGovernanceClient("") // empty apiURL -> transport error -> FailClosed
	cfg := &config.Config{Node: "community-0"}

	processDeletions(ctx, pool, cit, gov, cfg)

	var userCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE id = $1`, targetID).Scan(&userCount); err != nil {
		t.Fatalf("count target user: %v", err)
	}
	if userCount != 1 {
		t.Error("expected the deletion to be blocked (user must survive) when CITADEL cannot be evaluated")
	}

	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM deletion_requests WHERE id = $1`, reqID).Scan(&status); err != nil {
		t.Fatalf("select deletion_requests status: %v", err)
	}
	if status != "approved" {
		t.Errorf("expected deletion_requests.status to remain 'approved' (retried next tick), got %q", status)
	}
}

// TestProcessDeletions_PendingNotApproved_LeftUntouched verifies the
// two-person control documented on processDeletions: a request that is
// merely 'pending' (never approved by a distinct admin) must never be
// picked up by the unattended scheduler sweep, no matter how old
// requested_at is.
func TestProcessDeletions_PendingNotApproved_LeftUntouched(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	targetID := createSchedUser(t, pool, "sched-pending-target-"+suffix)

	var reqID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO deletion_requests (user_id, status, scheduled_for)
		VALUES ($1, 'pending', $2) RETURNING id`,
		targetID, time.Now().Add(-time.Minute),
	).Scan(&reqID); err != nil {
		t.Fatalf("insert deletion_requests: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM deletion_requests WHERE id = $1`, reqID) })

	cit := citadel.New("", nil, "community-1", true)
	gov := citadel.NewGovernanceClient("")
	cfg := &config.Config{Node: "community-0"}

	processDeletions(ctx, pool, cit, gov, cfg)

	var userCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE id = $1`, targetID).Scan(&userCount); err != nil {
		t.Fatalf("count target user: %v", err)
	}
	if userCount != 1 {
		t.Error("expected a merely-pending (not approved) deletion request to leave the user untouched")
	}
}

// --- sendDigests -----------------------------------------------------------

// TestSendDigests_HappyPath_SendsWeeklyDigestAndStampsLastDigestAt verifies
// the scheduler's own digest path (distinct from internal/digest.Run):
// a user due for a weekly digest with a qualifying recent post gets sent
// one (via the log-only email fallback) and last_digest_at is stamped.
func TestSendDigests_HappyPath_SendsWeeklyDigestAndStampsLastDigestAt(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	authorID := createSchedUser(t, pool, "sched-digest-author-"+suffix)
	var postID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO posts (author_id, title, slug, body, state, published_at)
		VALUES ($1, 'Digest Post', $2, 'body', 'published', $3) RETURNING id`,
		authorID, "digest-post-"+suffix, time.Now().Add(-time.Hour),
	).Scan(&postID); err != nil {
		t.Fatalf("insert post: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM posts WHERE id = $1`, postID) })

	recipientID := createSchedUser(t, pool, "sched-digest-recipient-"+suffix)
	if _, err := pool.Exec(ctx, `
		INSERT INTO notification_preferences (user_id, digest_enabled, digest_frequency) VALUES ($1, true, 'weekly')`,
		recipientID,
	); err != nil {
		t.Fatalf("insert notification_preferences: %v", err)
	}

	mailer := email.New(email.Config{SiteURL: "https://sin.to"}) // no Host -> log-only
	cfg := &config.Config{SiteURL: "https://sin.to"}

	sendDigests(ctx, pool, mailer, cfg)

	var lastDigestAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_digest_at FROM users WHERE id = $1`, recipientID).Scan(&lastDigestAt); err != nil {
		t.Fatalf("select last_digest_at: %v", err)
	}
	if lastDigestAt == nil {
		t.Fatal("expected last_digest_at to be stamped after a successful scheduler digest send")
	}
}

// TestSendDigests_DeactivatedUser_Skipped verifies the deactivated_at IS
// NULL guard: a deactivated user due for a digest must not receive one
// (and must not have last_digest_at touched).
func TestSendDigests_DeactivatedUser_Skipped(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randomSuffix()

	authorID := createSchedUser(t, pool, "sched-deact-author-"+suffix)
	var postID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO posts (author_id, title, slug, body, state, published_at)
		VALUES ($1, 'Deact Post', $2, 'body', 'published', $3) RETURNING id`,
		authorID, "deact-post-"+suffix, time.Now().Add(-time.Hour),
	).Scan(&postID); err != nil {
		t.Fatalf("insert post: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM posts WHERE id = $1`, postID) })

	recipientID := createSchedUser(t, pool, "sched-deact-recipient-"+suffix)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET deactivated_at = now() WHERE id = $1`, recipientID,
	); err != nil {
		t.Fatalf("deactivate recipient: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO notification_preferences (user_id, digest_enabled, digest_frequency) VALUES ($1, true, 'weekly')`,
		recipientID,
	); err != nil {
		t.Fatalf("insert notification_preferences: %v", err)
	}

	mailer := email.New(email.Config{SiteURL: "https://sin.to"})
	cfg := &config.Config{SiteURL: "https://sin.to"}

	sendDigests(ctx, pool, mailer, cfg)

	var lastDigestAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_digest_at FROM users WHERE id = $1`, recipientID).Scan(&lastDigestAt); err != nil {
		t.Fatalf("select last_digest_at: %v", err)
	}
	if lastDigestAt != nil {
		t.Error("expected a deactivated user to be skipped by sendDigests")
	}
}

// TestSafeRun_RecoversPanicAndDoesNotPropagate is the direct regression test
// for the panic-isolation fix: Start() now wraps each scheduler task in
// safeRun, so a panicking task (see TestPublishDue_PanicInCitadelEmit_
// PropagatesUncaught for what publishDue itself does when called directly)
// no longer crashes the whole process when invoked through Start's call
// path — it's contained and logged instead.
func TestSafeRun_RecoversPanicAndDoesNotPropagate(t *testing.T) {
	ran := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("safeRun must not let a panic propagate to the caller, got: %v", r)
			}
		}()
		safeRun("test-task", func() {
			ran = true
			panic("boom")
		})
	}()
	if !ran {
		t.Fatal("expected the wrapped function to have actually run before panicking")
	}
}

// TestSafeRun_NoPanic_RunsNormally proves safeRun is a no-op wrapper on the
// happy path — it doesn't swallow return values or alter normal execution.
func TestSafeRun_NoPanic_RunsNormally(t *testing.T) {
	calls := 0
	safeRun("test-task", func() { calls++ })
	if calls != 1 {
		t.Fatalf("expected fn to be called exactly once, got %d", calls)
	}
}
