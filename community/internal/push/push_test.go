package push_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/push"
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

// TestSendToUser_VAPIDNotConfigured_NoOp verifies SendToUser returns
// immediately (without touching the DB) when VAPID keys are absent. A nil
// pool would panic if the function tried to query it, so a clean return
// proves the no-op guard fired.
func TestSendToUser_VAPIDNotConfigured_NoOp(t *testing.T) {
	cfg := &config.Config{} // VAPIDPublicKey / VAPIDPrivateKey left empty
	push.SendToUser(context.Background(), nil, cfg, "user-1", push.Notification{
		Title: "Hi", Body: "there", URL: "https://sin.to",
	})
	// No panic and no assertion failure means the no-op guard worked.
}

// TestSendToUser_VAPIDConfigured_DBQueryFails_ReturnsWithoutSending verifies
// that a failing subscriptions query is handled by the error-handling guard
// (push.go's `if err != nil { return }` after the pool.Query call) rather
// than falling through to rows.Next()/push-sending, which would block or
// panic on a bad pool's zero-value rows. A bare "didn't panic" assertion
// isn't a real check here — a hang would silently pass too — so this
// asserts the function actually returns within a bounded time.
func TestSendToUser_VAPIDConfigured_DBQueryFails_ReturnsWithoutSending(t *testing.T) {
	cfg := &config.Config{
		VAPIDPublicKey:  "pub",
		VAPIDPrivateKey: "priv",
	}
	pool := newBadPool(t)

	done := make(chan struct{})
	go func() {
		push.SendToUser(context.Background(), pool, cfg, "user-1", push.Notification{
			Title: "Hi", Body: "there", URL: "https://sin.to",
		})
		close(done)
	}()

	select {
	case <-done:
		// Returned cleanly — the error-handling guard short-circuited
		// before reaching the push-sending path.
	case <-time.After(5 * time.Second):
		t.Fatal("SendToUser did not return within 5s after a failing DB query — it likely fell through the error-handling guard")
	}
}
