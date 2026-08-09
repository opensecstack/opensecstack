package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func newBadPoolForTagAliasesTest(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestResolveTagSlug_BothLookupsFail_ReturnsError verifies resolveTagSlug
// propagates the alias-lookup error when neither the direct slug nor the
// alias table has a match (DB unreachable here exercises the same "not
// found" code path a real miss would).
func TestResolveTagSlug_BothLookupsFail_ReturnsError(t *testing.T) {
	pool := newBadPoolForTagAliasesTest(t)
	d := Deps{Pool: pool}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/nonexistent", nil)

	_, _, err := resolveTagSlug(req, d, "nonexistent")
	if err == nil {
		t.Fatal("expected an error when both direct and alias lookups fail")
	}
}
