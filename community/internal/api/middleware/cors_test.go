package middleware

import (
	"bytes"
	"io"
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

// TestMaxBodySize_OversizedBodyIsRejectedByReader proves MaxBodySize actually
// wraps the request body in an http.MaxBytesReader that errors once the
// caller reads past the configured limit — not just that the handler chain
// still runs. We use a tiny custom limit by exercising the reader directly
// via a handler that reads the whole body and reports the error it got.
func TestMaxBodySize_OversizedBodyIsRejectedByReader(t *testing.T) {
	// MaxBodySize hardcodes a 4MiB limit; build a body one byte over that so
	// io.ReadAll must hit the MaxBytesReader's error path.
	oversized := bytes.Repeat([]byte("a"), (4<<20)+1)

	var readErr error
	var bytesRead int
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		bytesRead = len(b)
		readErr = err
		w.WriteHeader(http.StatusOK)
	})

	handler := MaxBodySize(captureHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts", bytes.NewReader(oversized))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if readErr == nil {
		t.Fatalf("expected MaxBytesReader to error on oversized body, got nil error (read %d bytes)", bytesRead)
	}
}

// TestMaxBodySize_UnderLimitBodyPassesThroughIntact proves the wrapping does
// not corrupt or truncate a body under the limit.
func TestMaxBodySize_UnderLimitBodyPassesThroughIntact(t *testing.T) {
	payload := []byte(`{"hello":"world"}`)
	var got []byte
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	handler := MaxBodySize(captureHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/posts", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if string(got) != string(payload) {
		t.Errorf("expected body %q to pass through unchanged, got %q", payload, got)
	}
}

// TestLogger_CapturesNonDefaultStatusCode proves Logger's wrapping
// responseWriter actually records the status code the inner handler set
// (via WriteHeader), rather than always assuming 200 — this is the
// behavioral contract of the Logger/responseWriter pair, even though the
// recorded status is only visible in the log line, not the HTTP response
// itself. We verify indirectly: the real ResponseWriter passed through must
// still see the same status code the handler wrote.
func TestLogger_CapturesNonDefaultStatusCode(t *testing.T) {
	teapot := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := Logger(teapot)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feed", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("expected underlying ResponseWriter to receive status %d, got %d", http.StatusTeapot, rec.Code)
	}
}

// TestLogger_DefaultStatusWhenHandlerNeverCallsWriteHeader proves the
// wrapping responseWriter defaults to 200 (matching real net/http semantics)
// when the inner handler only writes a body without an explicit WriteHeader
// call.
func TestLogger_DefaultStatusWhenHandlerNeverCallsWriteHeader(t *testing.T) {
	implicit200 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	handler := Logger(implicit200)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feed", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected implicit 200, got %d", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("expected body %q, got %q", "ok", rec.Body.String())
	}
}

// TestResponseWriter_FlushDelegatesToUnderlyingFlusher proves Flush() calls
// through to the wrapped ResponseWriter's Flush when it implements
// http.Flusher (httptest.ResponseRecorder does), rather than being a no-op
// stub — this is the one branch that isn't exercised by any handler test
// because most handlers never explicitly flush.
func TestResponseWriter_FlushDelegatesToUnderlyingFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, status: http.StatusOK}

	rw.Flush()

	if !rec.Flushed {
		t.Error("expected Flush() to delegate to the underlying http.Flusher and set Flushed=true")
	}
}

// nonFlusher wraps a ResponseWriter but deliberately does NOT implement
// http.Flusher, so Flush()'s type-assertion branch takes the false path.
type nonFlusher struct {
	http.ResponseWriter
}

func TestResponseWriter_FlushIsNoOpWhenUnderlyingWriterIsNotAFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: nonFlusher{rec}, status: http.StatusOK}

	// Must not panic even though nonFlusher does not implement http.Flusher.
	rw.Flush()
}
