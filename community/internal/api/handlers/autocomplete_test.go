package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestAutocomplete_ShortQuery_ReturnsEmptyResults(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/autocomplete?q=a", nil)
	w := httptest.NewRecorder()

	handlers.Autocomplete(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Posts []any `json:"posts"`
		Tags  []any `json:"tags"`
		Users []any `json:"users"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Posts) != 0 || len(resp.Tags) != 0 || len(resp.Users) != 0 {
		t.Errorf("expected all-empty results for short query, got %+v", resp)
	}
}

func TestAutocomplete_EmptyQuery_ReturnsEmptyResults(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/autocomplete", nil)
	w := httptest.NewRecorder()

	handlers.Autocomplete(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAutocomplete_LongEnoughQuery_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/autocomplete?q=security", nil)
	w := httptest.NewRecorder()

	handlers.Autocomplete(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}
