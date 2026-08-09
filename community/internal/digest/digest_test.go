package digest_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/digest"
	"github.com/opensecstack/community/internal/email"
)

// newBadPool returns a pool pointing at an unreachable address so queries
// fail fast without needing a real database.
func newBadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestRun_DigestDisabled_ReturnsNilWithoutTouchingDB(t *testing.T) {
	cfg := &config.Config{DigestEnabled: false}
	mailer := &email.Mailer{}

	// pool is nil: if Run tried to query the DB with digest disabled this
	// would panic on a nil pointer dereference, proving the early return.
	err := digest.Run(context.Background(), nil, mailer, cfg)
	if err != nil {
		t.Fatalf("expected nil error when digest disabled, got %v", err)
	}
}

func TestRun_DigestEnabled_DBQueryError_ReturnsError(t *testing.T) {
	cfg := &config.Config{DigestEnabled: true, SiteURL: "https://sin.to"}
	mailer := &email.Mailer{}
	pool := newBadPool(t)

	err := digest.Run(context.Background(), pool, mailer, cfg)
	if err == nil {
		t.Fatal("expected error when the posts query fails against an unreachable DB")
	}
}
