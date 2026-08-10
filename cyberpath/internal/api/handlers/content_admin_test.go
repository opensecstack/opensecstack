// Tests for ContentAdminHandler (content_admin.go).
package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Reload must fail closed with 503 when the content service was never
// wired — this is the "no DB configured" standalone-mode guard, and
// getting it wrong would mean a nil-pointer panic reaching an admin
// caller instead of a clean error response.
func TestContentAdminHandler_Reload_NoService(t *testing.T) {
	h := NewContentAdminHandler(nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/content/reload", nil)
	rec := httptest.NewRecorder()

	h.Reload()(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when content service is nil, got %d: %s", rec.Code, rec.Body.String())
	}
}
