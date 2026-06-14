package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// okHandler is a trivial handler that always returns 200.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestRateLimit_AllowsUpToLimit(t *testing.T) {
	const limit = 5
	rl := RateLimit(limit, time.Minute)
	handler := rl(okHandler)

	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimit_BlocksOnExceeded(t *testing.T) {
	const limit = 5
	rl := RateLimit(limit, time.Minute)
	handler := rl(okHandler)

	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.2:4321"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// The (limit+1)th request must be rejected.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:4321"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
}

func TestRateLimit_IsolatesIPs(t *testing.T) {
	const limit = 3
	rl := RateLimit(limit, time.Minute)
	handler := rl(okHandler)

	// Exhaust the limit for IP A.
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:9999"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// IP B must still be allowed.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.2:9999"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("IP B should not be rate-limited; got %d", rec.Code)
	}
}

func TestRateLimit_XForwardedFor(t *testing.T) {
	const limit = 2
	rl := RateLimit(limit, time.Minute)
	handler := rl(okHandler)

	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
		req.RemoteAddr = "10.0.0.1:80"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Now the proxied IP should be limited, even though RemoteAddr differs.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	req.RemoteAddr = "10.0.0.1:81" // port changes, real IP is the same
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for proxied IP, got %d", rec.Code)
	}
}

func TestRateLimit_WindowExpiry(t *testing.T) {
	// Use a very short window so we can observe expiry in a unit test.
	const limit = 2
	window := 100 * time.Millisecond
	rl := RateLimit(limit, window)
	handler := rl(okHandler)

	ip := "172.16.0.1:5000"

	// Exhaust the limit.
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Wait for the window to expire.
	time.Sleep(window + 20*time.Millisecond)

	// Should be allowed again.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after window expiry, got %d", rec.Code)
	}
}
