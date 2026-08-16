package handlers

// Shared test utilities for the OAuth/login handler tests in this package:
//   - a real Postgres pool (migrated on first use) for exercising the
//     find-or-create / account-linking DB logic that a stubbed "bad pool"
//     cannot reach, and
//   - a stub http.RoundTripper so oauth.go/oauth_google.go/oauth_sinauth.go's
//     calls to github.com, accounts.google.com, and the sinauth server can be
//     redirected to canned responses without any network access.
//
// These are exported (capitalized) so the external handlers_test package
// (auth_test.go, auth_methods_test.go, ...) can reuse them too — internal
// _test.go files become part of the `handlers` package for the test binary,
// so exported symbols they add are visible via a normal `handlers.` import
// from `handlers_test` files in the same package directory.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/db"
)

const defaultTestDBURL = "postgres://apiguard@localhost:5434/community_test?sslmode=disable"

var (
	testDBOnce sync.Once
	testDBPool *pgxpool.Pool
	testDBErr  error
)

// NewTestDBPool returns a shared, migrated pool against the OAuth test
// Postgres instance. Connection string is COMMUNITY_TEST_DB_URL if set,
// otherwise the local docker-compose test DB. Tests that need it call
// t.Skip via the returned ok flag when no DB is reachable, so this suite
// degrades gracefully in environments without Postgres.
func NewTestDBPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	testDBOnce.Do(func() {
		url := os.Getenv("COMMUNITY_TEST_DB_URL")
		if url == "" {
			url = defaultTestDBURL
		}
		pool, err := db.Connect(url, 5)
		if err != nil {
			testDBErr = err
			return
		}
		if err := db.Migrate(pool); err != nil {
			testDBErr = err
			return
		}
		testDBPool = pool
	})
	if testDBErr != nil {
		t.Skipf("real test DB unavailable, skipping DB-backed test: %v", testDBErr)
	}
	return testDBPool
}

// RandomSuffix returns a short random hex string for building collision-free
// usernames/emails in DB-backed tests that share the DB with other suites.
func RandomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CleanupUserByUsername deletes the given user row (and anything that
// cascades from it) at the end of a test, keeping the shared test DB tidy.
func CleanupUserByUsername(t *testing.T, pool *pgxpool.Pool, username string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE username = $1`, username)
	})
}

// newDepsWithBadDB mirrors handlers_test's helper of the same name (defined
// in health_test.go, package handlers_test) but lives in package handlers
// itself: internal white-box tests here (e.g. findOrCreateGitHubUser,
// ensureUniqueUsername) are unexported and can only be exercised from
// _test.go files inside package handlers.
func newDepsWithBadDB(t *testing.T) Deps {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	t.Cleanup(pool.Close)
	return Deps{Pool: pool, Cfg: &config.Config{}}
}

// RoundTripFunc adapts a function to http.RoundTripper so tests can stub
// oauthHTTPClient's transport without touching the network.
type RoundTripFunc func(*http.Request) (*http.Response, error)

func (f RoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// StubOAuthHTTPClient replaces oauthHTTPClient's Transport for the duration
// of the calling test and restores the original on cleanup. oauthHTTPClient
// is shared by GitHub/Google/sinauth OAuth code, so tests must not run
// t.Parallel() while it is stubbed.
func StubOAuthHTTPClient(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	orig := oauthHTTPClient.Transport
	oauthHTTPClient.Transport = rt
	t.Cleanup(func() { oauthHTTPClient.Transport = orig })
}
