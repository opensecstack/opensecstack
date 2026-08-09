package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestListTags_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags", nil)
	w := httptest.NewRecorder()

	handlers.ListTags(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestListPostsByTag_TagAndAliasNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/nonexistent/posts", nil)
	req.SetPathValue("slug", "nonexistent")
	w := httptest.NewRecorder()

	handlers.ListPostsByTag(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when both tag and alias lookups fail, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestGetPopularTags_DBError_Returns200WithEmptyTags verifies GetPopularTags
// deliberately degrades gracefully (200 + empty list) on a query failure
// instead of a 500, since it's typically used for non-critical UI chrome.
func TestGetPopularTags_DBError_Returns200WithEmptyTags(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/popular", nil)
	w := httptest.NewRecorder()

	handlers.GetPopularTags(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even on db error, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Tags []any `json:"tags"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Tags == nil || len(resp.Tags) != 0 {
		t.Errorf("expected empty tags array, got %v", resp.Tags)
	}
}

func TestGetTag_TagAndAliasNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tags/nonexistent", nil)
	req.SetPathValue("slug", "nonexistent")
	w := httptest.NewRecorder()

	handlers.GetTag(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d — body: %s", w.Code, w.Body.String())
	}
}
