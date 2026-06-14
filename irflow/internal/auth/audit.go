package auth

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

// AuditLog returns middleware that records every API request as a structured
// log line including the authenticated user, path, status, and duration. It
// is safe to mount before the Middleware; requests without claims log with
// user="anonymous".
func AuditLog(logger *zap.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			userID := "anonymous"
			role := ""
			if c := ClaimsFromContext(r.Context()); c != nil {
				userID = c.Subject
				role = c.Role
			}

			logger.Info("api request",
				zap.String("request_id", middleware.GetReqID(r.Context())),
				zap.String("user_id", userID),
				zap.String("role", role),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", rec.status),
				zap.Duration("duration", time.Since(start)),
				zap.String("remote", r.RemoteAddr),
			)
		})
	}
}

// statusRecorder captures the response status so AuditLog can include it.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
