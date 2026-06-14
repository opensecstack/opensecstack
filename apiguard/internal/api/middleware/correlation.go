package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// contextKey is an unexported type for context keys in this package to avoid
// collisions with keys from other packages.
type contextKey string

// correlationIDKey is the context key under which the correlation ID is stored.
const correlationIDKey contextKey = "correlation_id"

// CorrelationID is a middleware that ensures every request carries a valid
// UUID correlation ID. It reads the X-Request-ID header from the incoming
// request, validates it as a UUID, and generates a new one when the header is
// absent or contains an invalid value. The resolved ID is stored in the request
// context (accessible via GetCorrelationID) and echoed back in the
// X-Request-ID response header.
func CorrelationID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")

		// Validate the inbound ID. If it is absent or not a valid UUID,
		// generate a fresh one.
		if _, err := uuid.Parse(id); err != nil {
			id = uuid.New().String()
		}

		// Propagate the correlation ID through the request context so that
		// downstream handlers and log statements can retrieve it without
		// inspecting HTTP headers directly.
		ctx := context.WithValue(r.Context(), correlationIDKey, id)

		// Echo the ID back to the caller so they can correlate client-side
		// logs with server-side logs.
		w.Header().Set("X-Request-ID", id)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetCorrelationID retrieves the correlation ID stored in ctx by the
// CorrelationID middleware. It returns an empty string when no ID is present
// (e.g. in unit tests that do not pass the request through the middleware).
func GetCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return id
	}
	return ""
}
