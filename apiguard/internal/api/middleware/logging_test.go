package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

// makeStatusHandler returns an http.HandlerFunc that always responds with the
// given HTTP status code and no body.
func makeStatusHandler(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}
}

// applyRequestLogger wraps next with RequestLogger (nop logger, no trusted proxies),
// fires req through it, and returns the recorded response.
func applyRequestLogger(next http.Handler, req *http.Request) *httptest.ResponseRecorder {
	logger := zerolog.Nop()
	wrapped := RequestLogger(logger, nil)(next)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	return rr
}

// TestRequestLogger_CallsNext verifies that the middleware does not swallow the
// request — the downstream handler is always invoked.
func TestRequestLogger_CallsNext(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", nil)
	applyRequestLogger(next, req)

	if !called {
		t.Error("downstream handler was not called by RequestLogger")
	}
}

// TestRequestLogger_PassesThrough200 verifies that a 200 response from the
// downstream handler is propagated unchanged.
func TestRequestLogger_PassesThrough200(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	rr := applyRequestLogger(makeStatusHandler(http.StatusOK), req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestRequestLogger_PassesThrough404 verifies that a 404 from downstream is
// not altered by the logging middleware.
func TestRequestLogger_PassesThrough404(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/missing", nil)
	rr := applyRequestLogger(makeStatusHandler(http.StatusNotFound), req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// TestRequestLogger_PassesThrough500 verifies that a 500 from downstream is
// not altered by the logging middleware.
func TestRequestLogger_PassesThrough500(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/boom", nil)
	rr := applyRequestLogger(makeStatusHandler(http.StatusInternalServerError), req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

// TestRequestLogger_MethodsAndPaths exercises the middleware with a variety of
// HTTP methods and paths to confirm it does not block or modify any of them.
func TestRequestLogger_MethodsAndPaths(t *testing.T) {
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/scans"},
		{http.MethodPost, "/api/v1/api-keys"},
		{http.MethodDelete, "/api/v1/api-keys/some-id"},
		{http.MethodPatch, "/api/v1/findings/some-id"},
		{http.MethodOptions, "/api/v1/scans"},
	}

	logger := zerolog.Nop()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var gotMethod, gotPath string
			capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				gotPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
			wrapped := RequestLogger(logger, nil)(capture)
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rr.Code)
			}
			if gotMethod != tc.method {
				t.Errorf("downstream received method %q, want %q", gotMethod, tc.method)
			}
			if gotPath != tc.path {
				t.Errorf("downstream received path %q, want %q", gotPath, tc.path)
			}
		})
	}
}

// TestRequestLogger_NilTrustedProxies confirms that passing nil for trusted
// proxies does not panic and still produces a valid response.
func TestRequestLogger_NilTrustedProxies(t *testing.T) {
	logger := zerolog.Nop()
	wrapped := RequestLogger(logger, nil)(makeStatusHandler(http.StatusOK))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	// Should not panic.
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestRequestLogger_ResponseBodyPassedThrough verifies that a body written by
// the downstream handler is visible in the recorded response (the middleware
// must not consume or discard it).
func TestRequestLogger_ResponseBodyPassedThrough(t *testing.T) {
	const want = `{"ok":true}`
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(want))
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rr := applyRequestLogger(next, req)

	if got := rr.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}
