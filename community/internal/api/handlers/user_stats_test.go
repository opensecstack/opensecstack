package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestGetUserStats_UserNotFound_Returns500(t *testing.T) {
	// With an unreachable DB, the initial user lookup fails with a
	// connection error (not pgx.ErrNoRows), so the handler takes the
	// generic 500 branch rather than the 404 "user not found" branch.
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/alice/stats", nil)
	req.SetPathValue("username", "alice")
	w := httptest.NewRecorder()

	handlers.GetUserStats(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db connection error, got %d — body: %s", w.Code, w.Body.String())
	}
}
