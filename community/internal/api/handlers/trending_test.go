package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestListTrendingFeed_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/trending", nil)
	w := httptest.NewRecorder()

	handlers.ListTrendingFeed(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestListTrendingFeed_CustomLimitOffset_StillHitsDB(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/trending?limit=5&offset=10", nil)
	w := httptest.NewRecorder()

	handlers.ListTrendingFeed(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error with custom paging, got %d", w.Code)
	}
}
