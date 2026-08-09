package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestFeedList_NilStoreReturnsEmpty(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/feeds", nil)

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	feeds, _ := body["feeds"].([]any)
	if len(feeds) != 0 {
		t.Errorf("expected empty feeds, got %v", feeds)
	}
}

func TestFeedCreate_PersistenceDisabledReturns503(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/feeds", strings.NewReader(`{"name":"x","feed_type":"csv"}`))

	h.Create(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestFeedGet_NilStoreReturns404(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/feeds/x", nil)

	h.Get(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestFeedPatch_NilStoreReturns503(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/feeds/x", strings.NewReader(`{"enabled":true}`))

	h.Patch(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestFeedDelete_NilStoreReturns503(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/feeds/x", nil)

	h.Delete(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestValidFeedType(t *testing.T) {
	cases := map[string]bool{
		"taxii21": true, "csv": true, "misp": true, "manual": true,
		"": false, "unknown": false,
	}
	for ty, want := range cases {
		if got := validFeedType(ty); got != want {
			t.Errorf("validFeedType(%q) = %v, want %v", ty, got, want)
		}
	}
}
