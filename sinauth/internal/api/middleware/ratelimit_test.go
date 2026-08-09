package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimit_AllowsUnderLimit(t *testing.T) {
	mw := RateLimit(3, time.Minute)
	h := mw(okHandler())

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, http.StatusOK)
		}
	}
}

func TestRateLimit_BlocksOverLimit(t *testing.T) {
	mw := RateLimit(2, time.Minute)
	h := mw(okHandler())

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "1.2.3.4:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, http.StatusOK)
		}
	}

	// The 3rd request from the same IP within the window must be rejected.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}
	if retry := rec.Header().Get("Retry-After"); retry != "60" {
		t.Errorf("Retry-After = %q, want 60", retry)
	}
}

func TestRateLimit_SeparateIPsHaveSeparateCounters(t *testing.T) {
	mw := RateLimit(1, time.Minute)
	h := mw(okHandler())

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "1.1.1.1:1111"
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("ip1 first request: status = %d, want %d", rec1.Code, http.StatusOK)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "2.2.2.2:2222"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("ip2 first request: status = %d, want %d (should not share ip1's counter)", rec2.Code, http.StatusOK)
	}
}

func TestRateLimit_SeparateInstancesHaveIsolatedCounters(t *testing.T) {
	mw1 := RateLimit(1, time.Minute)
	mw2 := RateLimit(1, time.Minute)
	h1 := mw1(okHandler())
	h2 := mw2(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "9.9.9.9:9999"
	rec := httptest.NewRecorder()
	h1.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("h1 first request: status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Same IP hitting a completely separate RateLimit() instance must not be
	// throttled by h1's counter.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "9.9.9.9:9999"
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("h2 first request: status = %d, want %d (counters must be isolated per instance)", rec2.Code, http.StatusOK)
	}
}

func TestClientIP_UsesXFFOnlyForTrustedProxy(t *testing.T) {
	trusted := map[string]struct{}{"10.0.0.1": {}}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")

	got := clientIP(req, trusted)
	if got != "203.0.113.5" {
		t.Errorf("clientIP = %q, want 203.0.113.5 (first XFF entry)", got)
	}
}

func TestClientIP_IgnoresXFFFromUntrustedRemote(t *testing.T) {
	trusted := map[string]struct{}{"10.0.0.1": {}}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.99:12345" // not in the trusted set
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	got := clientIP(req, trusted)
	if got != "203.0.113.99" {
		t.Errorf("clientIP = %q, want RemoteAddr host 203.0.113.99 (XFF from untrusted source must be ignored)", got)
	}
}

func TestClientIP_NoXFFHeaderUsesRemoteAddr(t *testing.T) {
	trusted := map[string]struct{}{"10.0.0.1": {}}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	got := clientIP(req, trusted)
	if got != "10.0.0.1" {
		t.Errorf("clientIP = %q, want 10.0.0.1", got)
	}
}
