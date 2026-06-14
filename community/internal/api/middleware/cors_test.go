package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testOrigin = "http://localhost:3000"

func TestCORS_OptionsPreflightReturns204WithHeaders(t *testing.T) {
	handler := CORS([]string{testOrigin})(okHandler)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/posts", nil)
	req.Header.Set("Origin", testOrigin)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("OPTIONS preflight: expected 204, got %d", rec.Code)
	}

	want := map[string]string{
		"Access-Control-Allow-Origin":  testOrigin,
		"Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
		"Access-Control-Allow-Headers": "Authorization,Content-Type",
	}
	for header, expected := range want {
		if got := rec.Header().Get(header); got != expected {
			t.Errorf("preflight header %s: expected %q, got %q", header, expected, got)
		}
	}
}

func TestCORS_OptionsPreflightDoesNotCallNext(t *testing.T) {
	var nextCalled bool
	sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := CORS([]string{testOrigin})(sentinel)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/posts", nil)
	req.Header.Set("Origin", testOrigin)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next handler must not be called for OPTIONS preflight")
	}
}

func TestCORS_RegularRequestPassesThroughWithHeaders(t *testing.T) {
	handler := CORS([]string{testOrigin})(okHandler)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/feed", nil)
		req.Header.Set("Origin", testOrigin)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", method, rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testOrigin {
			t.Errorf("%s: expected Access-Control-Allow-Origin=%q, got %q", method, testOrigin, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
			t.Errorf("%s: Access-Control-Allow-Methods header missing", method)
		}
		if got := rec.Header().Get("Access-Control-Allow-Headers"); got == "" {
			t.Errorf("%s: Access-Control-Allow-Headers header missing", method)
		}
	}
}

func TestCORS_UnknownOriginGetsNoACHeaders(t *testing.T) {
	handler := CORS([]string{testOrigin})(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feed", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("unknown origin must not receive ACAO header, got %q", got)
	}
}
