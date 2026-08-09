package middleware

import (
	"net/http"
	"strings"
)

// SecurityHeaders returns a middleware that sets common security-related HTTP
// response headers on every response. For responses whose Content-Type
// contains "text/html" an additional Content-Security-Policy header is added.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap the ResponseWriter so we can inspect the Content-Type that the
		// downstream handler sets before the headers are sent to the client.
		srw := &securityHeadersWriter{ResponseWriter: w}
		next.ServeHTTP(srw, r)
		// If the response has not been written yet (e.g. the handler did not
		// call WriteHeader), flush the headers now.
		srw.writeSecurityHeaders()
	})
}

// securityHeadersWriter wraps http.ResponseWriter and injects security headers
// just before the first call to WriteHeader (or Write, which implicitly calls
// WriteHeader with 200).
type securityHeadersWriter struct {
	http.ResponseWriter
	headersSent bool
}

func (s *securityHeadersWriter) writeSecurityHeaders() {
	if s.headersSent {
		return
	}
	s.headersSent = true
	h := s.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-XSS-Protection", "1; mode=block")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Add CSP only for HTML responses.
	if strings.Contains(h.Get("Content-Type"), "text/html") {
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	}
}

func (s *securityHeadersWriter) WriteHeader(code int) {
	s.writeSecurityHeaders()
	s.ResponseWriter.WriteHeader(code)
}

func (s *securityHeadersWriter) Write(b []byte) (int, error) {
	s.writeSecurityHeaders()
	return s.ResponseWriter.Write(b)
}
