package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestGetSpaceUnreadCounts_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/s/unread", nil)
	w := httptest.NewRecorder()

	handlers.GetSpaceUnreadCounts(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestGetSpaceUnreadCounts_SpaceNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/spaces/s/unread", nil)
	req.SetPathValue("slug", "s")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetSpaceUnreadCounts(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestMarkChannelRead_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{Cfg: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/s/channels/c/read", nil)
	w := httptest.NewRecorder()

	handlers.MarkChannelRead(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

// MarkChannelRead is idempotent: an unresolvable channel still returns 204.
func TestMarkChannelRead_ChannelNotFound_StillReturns204(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/spaces/s/channels/c/read", nil)
	req.SetPathValue("slug", "s")
	req.SetPathValue("channel", "c")
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.MarkChannelRead(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 (idempotent) even when channel lookup fails, got %d", w.Code)
	}
}
