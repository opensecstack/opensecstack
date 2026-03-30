package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORS(t *testing.T) {
	// makeNext builds a downstream handler that records whether it was called.
	makeNext := func(t *testing.T) (http.Handler, *bool) {
		t.Helper()
		called := false
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		return h, &called
	}

	tests := []struct {
		name               string
		allowedOrigins     []string
		method             string
		origin             string
		wantStatus         int
		wantNextCalled     bool
		wantACAO           string // Access-Control-Allow-Origin
		wantVary           bool   // expect Vary: Origin header
		wantNoACAO         bool   // explicitly assert header is absent
	}{
		// 1. Empty origins + preflight → 403, next NOT called
		{
			name:           "empty origins preflight denied",
			allowedOrigins: []string{},
			method:         http.MethodOptions,
			origin:         "https://evil.com",
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
			wantNoACAO:     true,
		},
		// 2. Empty origins + regular request → passes through, no CORS headers
		{
			name:           "empty origins regular request passes through",
			allowedOrigins: []string{},
			method:         http.MethodGet,
			origin:         "https://evil.com",
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			wantNoACAO:     true,
		},
		// 3. Wildcard + preflight → 204, header = *
		{
			name:           "wildcard preflight allowed",
			allowedOrigins: []string{"*"},
			method:         http.MethodOptions,
			origin:         "https://any.com",
			wantStatus:     http.StatusNoContent,
			wantNextCalled: false,
			wantACAO:       "*",
		},
		// 4. Wildcard + regular request → passes through, header = *
		{
			name:           "wildcard regular request allowed",
			allowedOrigins: []string{"*"},
			method:         http.MethodGet,
			origin:         "https://any.com",
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			wantACAO:       "*",
		},
		// 5. Explicit allowed origin + matching preflight → 204, correct header + Vary
		{
			name:           "explicit origin matching preflight",
			allowedOrigins: []string{"https://allowed.com"},
			method:         http.MethodOptions,
			origin:         "https://allowed.com",
			wantStatus:     http.StatusNoContent,
			wantNextCalled: false,
			wantACAO:       "https://allowed.com",
			wantVary:       true,
		},
		// 6. Explicit allowed origin + non-matching preflight → 403
		{
			name:           "explicit origin non-matching preflight denied",
			allowedOrigins: []string{"https://allowed.com"},
			method:         http.MethodOptions,
			origin:         "https://notallowed.com",
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
			wantNoACAO:     true,
		},
		// 7. Explicit allowed origin + matching regular request → passes through + CORS headers
		{
			name:           "explicit origin matching regular request",
			allowedOrigins: []string{"https://allowed.com"},
			method:         http.MethodGet,
			origin:         "https://allowed.com",
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			wantACAO:       "https://allowed.com",
			wantVary:       true,
		},
		// 8. Explicit allowed origin + non-matching regular request → passes through, no CORS headers
		{
			name:           "explicit origin non-matching regular request passes through",
			allowedOrigins: []string{"https://allowed.com"},
			method:         http.MethodGet,
			origin:         "https://notallowed.com",
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			wantNoACAO:     true,
		},
		// 9. No Origin header → no CORS headers, passes through
		{
			name:           "no origin header passes through no cors headers",
			allowedOrigins: []string{"https://allowed.com"},
			method:         http.MethodGet,
			origin:         "", // no Origin header
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			wantNoACAO:     true,
		},
		// 10. Multiple allowed origins, second one matches
		{
			name:           "multiple origins second one matches",
			allowedOrigins: []string{"https://first.com", "https://second.com"},
			method:         http.MethodGet,
			origin:         "https://second.com",
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			wantACAO:       "https://second.com",
			wantVary:       true,
		},
		// Bonus: multiple origins, preflight for second origin
		{
			name:           "multiple origins second one matches preflight",
			allowedOrigins: []string{"https://first.com", "https://second.com"},
			method:         http.MethodOptions,
			origin:         "https://second.com",
			wantStatus:     http.StatusNoContent,
			wantNextCalled: false,
			wantACAO:       "https://second.com",
			wantVary:       true,
		},
		// No Origin header + preflight → 403 (no origin = not allowed)
		{
			name:           "no origin preflight denied",
			allowedOrigins: []string{"https://allowed.com"},
			method:         http.MethodOptions,
			origin:         "",
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
			wantNoACAO:     true,
		},
		// Wildcard + no origin header preflight → 403 (empty origin is still not allowed)
		{
			name:           "wildcard no origin header preflight denied",
			allowedOrigins: []string{"*"},
			method:         http.MethodOptions,
			origin:         "",
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
			wantNoACAO:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next, called := makeNext(t)
			handler := CORS(tc.allowedOrigins)(next)

			req := httptest.NewRequest(tc.method, "/api/test", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Check status code.
			if rr.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tc.wantStatus)
			}

			// Check whether next was called.
			if *called != tc.wantNextCalled {
				t.Errorf("next called = %v, want %v", *called, tc.wantNextCalled)
			}

			// Check Access-Control-Allow-Origin header.
			acao := rr.Header().Get("Access-Control-Allow-Origin")
			if tc.wantACAO != "" && acao != tc.wantACAO {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", acao, tc.wantACAO)
			}
			if tc.wantNoACAO && acao != "" {
				t.Errorf("Access-Control-Allow-Origin = %q, want it absent", acao)
			}

			// Check Vary header.
			if tc.wantVary {
				vary := rr.Header().Get("Vary")
				if vary == "" {
					t.Error("Vary header absent, want 'Origin'")
				}
			}

			// When an explicit (non-wildcard, non-empty) allowed origin is set and
			// the origin matches, verify the additional CORS headers are present too.
			if tc.wantACAO != "" && tc.wantACAO != "*" {
				if rr.Header().Get("Access-Control-Allow-Methods") == "" {
					t.Error("Access-Control-Allow-Methods absent on allowed response")
				}
				if rr.Header().Get("Access-Control-Allow-Headers") == "" {
					t.Error("Access-Control-Allow-Headers absent on allowed response")
				}
				if rr.Header().Get("Access-Control-Max-Age") == "" {
					t.Error("Access-Control-Max-Age absent on allowed response")
				}
			}

			// Wildcard case: also check the additional CORS headers.
			if tc.wantACAO == "*" {
				if rr.Header().Get("Access-Control-Allow-Methods") == "" {
					t.Error("Access-Control-Allow-Methods absent on wildcard allowed response")
				}
			}
		})
	}
}
