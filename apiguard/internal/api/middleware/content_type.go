package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
)

// RequireJSONContentType rejects POST, PUT, and PATCH requests whose
// Content-Type is set but is not application/json.  Requests that omit the
// header entirely are allowed through so that simple curl calls without an
// explicit Content-Type do not break.
func RequireJSONContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			if ct != "" && !strings.HasPrefix(ct, "application/json") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnsupportedMediaType)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Content-Type must be application/json"}) //nolint:errcheck
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
