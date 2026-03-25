package middleware

import (
	"net/http"
)

// CORS returns a middleware that adds Cross-Origin Resource Sharing headers.
//
// If allowedOrigins is empty or contains only "*", every origin is permitted
// (development / wildcard mode). Otherwise the Origin request header is checked
// against the provided list; unmatched origins receive no CORS headers.
//
// Preflight OPTIONS requests are answered with 204 No Content immediately,
// before any authentication middleware runs.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	// Pre-compute wildcard mode.
	wildcard := len(allowedOrigins) == 0
	if !wildcard {
		for _, o := range allowedOrigins {
			if o == "*" {
				wildcard = true
				break
			}
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
					// Origin not in allowed list: still return 204 but without
					// CORS headers so the browser will block the preflight.
					w.WriteHeader(http.StatusNoContent)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
