package middleware

import (
	"net/http"
)

// CORS returns a middleware that adds Cross-Origin Resource Sharing headers.
//
// If allowedOrigins contains only "*", every origin is permitted (wildcard
// mode). If allowedOrigins is empty, all cross-origin requests are denied —
// explicit configuration is required. Otherwise the Origin request header is
// checked against the provided list; unmatched origins receive no CORS headers.
//
// Preflight OPTIONS requests are answered with 204 No Content immediately,
// before any authentication middleware runs.
//
// Security defaults:
//   - Passing an empty allowedOrigins slice (or omitting cors configuration)
//     denies all origins by default. No wildcard is assumed. Operators who
//     expect browser clients to reach the API MUST explicitly list the allowed
//     origins in the configuration.
//   - Non-OPTIONS (non-preflight) requests pass through to downstream handlers
//     without CORS headers being added when the origin is not in the allowlist.
//     The browser will block the response on the client side, but the request
//     itself still reaches the server; authentication and authorisation
//     middleware remain responsible for protecting those endpoints.
//   - The allowlist is an exact-match set; wildcard subdomains are not
//     supported. Use an explicit list of fully qualified origins.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	// Pre-compute wildcard mode. An empty list is NOT wildcard — it denies all.
	wildcard := false
	for _, o := range allowedOrigins {
		if o == "*" {
			wildcard = true
			break
		}
	}

	// Build a fast lookup set.
	originSet := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Determine whether this origin is allowed.
			allowed := origin != "" && (wildcard || func() bool {
				_, ok := originSet[origin]
				return ok
			}())

			if allowed {
				if wildcard {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Add("Vary", "Origin")
				}
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// Respond to preflight immediately — do NOT forward to downstream
			// handlers (which would include auth middleware).
			if r.Method == http.MethodOptions {
				if allowed {
					w.WriteHeader(http.StatusNoContent)
				} else {
					// Origin not in allowed list: return 403 so the browser
					// receives an explicit rejection rather than an ambiguous 204.
					w.WriteHeader(http.StatusForbidden)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
