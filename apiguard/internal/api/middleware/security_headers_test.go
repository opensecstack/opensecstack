package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// makeSecHandler wraps a downstream handler with SecurityHeaders and returns the
// recorded response after a single GET request.
func makeSecHandler(next http.Handler) *httptest.ResponseRecorder {
	wrapped := SecurityHeaders(next)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	return rr
}

// baseSecurityHeaders lists the four headers that must be present on every
// response regardless of Content-Type.
var baseSecurityHeaders = map[string]string{
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options":        "DENY",
	"X-XSS-Protection":       "1; mode=block",
	"Referrer-Policy":        "strict-origin-when-cross-origin",
}

func assertBaseHeaders(t *testing.T, h http.Header) {
	t.Helper()
	for name, want := range baseSecurityHeaders {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// TestSecurityHeaders_BaseHeadersOnJSONResponse checks that all four base security
// headers are set when the downstream handler returns a JSON response.
func TestSecurityHeaders_BaseHeadersOnJSONResponse(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	})
	rr := makeSecHandler(next)
	assertBaseHeaders(t, rr.Header())
}

// TestSecurityHeaders_NoCSSOnJSONResponse checks that the Content-Security-Policy
// header is NOT set for a plain JSON response.
func TestSecurityHeaders_NoCSSOnJSONResponse(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	})
	rr := makeSecHandler(next)
	if got := rr.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("Content-Security-Policy = %q, want absent for JSON response", got)
	}
}

// TestSecurityHeaders_CSPOnHTMLResponse checks that the Content-Security-Policy
// header IS set when the downstream handler returns a text/html response.
func TestSecurityHeaders_CSPOnHTMLResponse(t *testing.T) {
	const wantCSP = "default-src 'none'; style-src 'unsafe-inline'"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
	})
	rr := makeSecHandler(next)
	assertBaseHeaders(t, rr.Header())

	if got := rr.Header().Get("Content-Security-Policy"); got != wantCSP {
		t.Errorf("Content-Security-Policy = %q, want %q", got, wantCSP)
	}
}

// TestSecurityHeaders_ExplicitWriteHeader verifies headers are injected even
// when the downstream handler calls WriteHeader explicitly (e.g. 404).
func TestSecurityHeaders_ExplicitWriteHeader(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	})
	rr := makeSecHandler(next)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
	assertBaseHeaders(t, rr.Header())
}

// TestSecurityHeaders_ImplicitWriteHeader verifies headers are injected when
// the downstream handler calls Write() without an explicit WriteHeader call,
// which implicitly sends a 200 status.
func TestSecurityHeaders_ImplicitWriteHeader(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		// No explicit WriteHeader — Write triggers implicit 200.
	})
	rr := makeSecHandler(next)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	assertBaseHeaders(t, rr.Header())
}

// TestSecurityHeaders_On500Response verifies headers are present on a 500 error response.
func TestSecurityHeaders_On500Response(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
	})
	rr := makeSecHandler(next)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	assertBaseHeaders(t, rr.Header())
}

// TestSecurityHeaders_TableDriven runs a compact table-driven sweep over a
// variety of status codes and Content-Types to confirm the invariants hold
// consistently.
func TestSecurityHeaders_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		statusCode  int
		wantCSP     bool
	}{
		{"200 JSON", "application/json", http.StatusOK, false},
		{"200 HTML", "text/html", http.StatusOK, true},
		{"200 HTML charset", "text/html; charset=utf-8", http.StatusOK, true},
		{"201 JSON", "application/json", http.StatusCreated, false},
		{"301 no body", "", http.StatusMovedPermanently, false},
		{"400 JSON", "application/json", http.StatusBadRequest, false},
		{"401 JSON", "application/json", http.StatusUnauthorized, false},
		{"403 HTML", "text/html", http.StatusForbidden, true},
		{"404 JSON", "application/json", http.StatusNotFound, false},
		{"500 JSON", "application/json", http.StatusInternalServerError, false},
		{"200 plain text", "text/plain", http.StatusOK, false},
	}

	const wantCSP = "default-src 'none'; style-src 'unsafe-inline'"

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(tc.statusCode)
			})
			rr := makeSecHandler(next)

			if rr.Code != tc.statusCode {
				t.Errorf("status = %d, want %d", rr.Code, tc.statusCode)
			}

			assertBaseHeaders(t, rr.Header())

			csp := rr.Header().Get("Content-Security-Policy")
			if tc.wantCSP && csp != wantCSP {
				t.Errorf("Content-Security-Policy = %q, want %q", csp, wantCSP)
			}
			if !tc.wantCSP && csp != "" {
				t.Errorf("Content-Security-Policy = %q, want absent", csp)
			}
		})
	}
}

// TestSecurityHeaders_HandlerNotCalledTwice ensures that the security-headers
// wrapper does not cause double-invocation of the downstream handler or any
// double-write of headers.
func TestSecurityHeaders_HandlerNotCalledTwice(t *testing.T) {
	callCount := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	})
	makeSecHandler(next)
	if callCount != 1 {
		t.Errorf("downstream handler called %d times, want 1", callCount)
	}
}

// TestSecurityHeaders_HeadersSetOnlyOnce confirms that calling WriteHeader and
// then Write does not duplicate the security headers (the idempotency guard in
// securityHeadersWriter.writeSecurityHeaders must prevent re-injection).
func TestSecurityHeaders_HeadersSetOnlyOnce(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
	})
	rr := makeSecHandler(next)

	// Header().Values returns all values for the key; there must be exactly one.
	for name := range baseSecurityHeaders {
		values := rr.Header().Values(name)
		if len(values) != 1 {
			t.Errorf("%s set %d times, want exactly 1", name, len(values))
		}
	}
}
