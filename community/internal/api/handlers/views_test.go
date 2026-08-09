package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

// TestRecordView_DBError_StillReturns204 verifies RecordView is
// best-effort: both Exec calls discard their errors, so even against an
// unreachable DB the handler always answers 204.
func TestRecordView_DBError_StillReturns204(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts/1/view", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()

	handlers.RecordView(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 regardless of db error, got %d — body: %s", w.Code, w.Body.String())
	}
}
