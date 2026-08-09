package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/citadel"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/email"
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

// TestPublishDue_DBQueryError_ReturnsWithoutPanic verifies publishDue handles
// a failing UPDATE...RETURNING query gracefully (logs and returns) rather
// than panicking, since it has no error return to the caller.
func TestPublishDue_DBQueryError_ReturnsWithoutPanic(t *testing.T) {
	pool := newBadPool(t)
	cit := citadel.New("http://localhost:1", nil, "community-1", true)
	cfg := &config.Config{Node: "community-0"}

	publishDue(context.Background(), pool, cit, cfg)
	// Reaching here without panicking proves the error branch returned cleanly.
}

// TestProcessDeletions_DBQueryError_ReturnsWithoutPanic verifies
// processDeletions handles a failing SELECT query gracefully.
func TestProcessDeletions_DBQueryError_ReturnsWithoutPanic(t *testing.T) {
	pool := newBadPool(t)
	cit := citadel.New("http://localhost:1", nil, "community-1", true)
	gov := citadel.NewGovernanceClient("http://localhost:1")
	cfg := &config.Config{Node: "community-0"}

	processDeletions(context.Background(), pool, cit, gov, cfg)
}

// TestSendDigests_DBQueryError_ReturnsWithoutPanic verifies sendDigests
// handles a failing SELECT query gracefully.
func TestSendDigests_DBQueryError_ReturnsWithoutPanic(t *testing.T) {
	pool := newBadPool(t)
	mailer := email.New(email.Config{SiteURL: "https://sin.to"})
	cfg := &config.Config{SiteURL: "https://sin.to"}

	sendDigests(context.Background(), pool, mailer, cfg)
}

// TestStart_ExitsOnContextCancellation verifies the background loop honours
// ctx.Done() and returns instead of looping forever — critical since Start
// is meant to be launched as a goroutine and must be stoppable on shutdown.
func TestStart_ExitsOnContextCancellation(t *testing.T) {
	pool := newBadPool(t)
	cfg := &config.Config{Node: "community-0", CitadelDryRun: true}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Start(ctx, pool, cfg)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Start returned promptly after cancellation, as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within timeout after context cancellation")
	}
}
