package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestGetAdminStats_NonModerator_Returns403(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/stats", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetAdminStats(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

// TestGetAdminStats_DBError_StillReturns200WithZeroedStats verifies the
// handler's best-effort design: every stat query error is swallowed (Scan
// errors are ignored, nil slices default to empty), so a moderator always
// gets a 200 with a well-formed (if zeroed) stats object rather than a 500.
func TestGetAdminStats_DBError_StillReturns200WithZeroedStats(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/stats", nil)
	req = withClaims(req, &auth.Claims{Sub: "mod1", Role: "moderator"})
	w := httptest.NewRecorder()

	handlers.GetAdminStats(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even on db error, got %d — body: %s", w.Code, w.Body.String())
	}

	var got struct {
		TotalUsers int   `json:"total_users"`
		TopTags    []any `json:"top_tags"`
		TopAuthors []any `json:"top_authors"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.TotalUsers != 0 {
		t.Errorf("expected TotalUsers=0 on db error, got %d", got.TotalUsers)
	}
	if got.TopTags == nil {
		t.Error("expected top_tags to be an empty array, not null")
	}
	if got.TopAuthors == nil {
		t.Error("expected top_authors to be an empty array, not null")
	}
}
