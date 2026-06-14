package audit

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/auth"
)

// MetricsHook is the optional metrics surface — kept narrow so audit
// doesn't depend on the metrics package directly.
type MetricsHook interface {
	IncAuditEvent(outcome string)
}

// Middleware emits an Event for every state-changing /api/v1/* call.
// GETs are deliberately skipped: they balloon the audit log and aren't
// state-changing. Auth failures are still captured because this sits
// *outside* the auth middleware.
func Middleware(sink Sink, logger *zerolog.Logger, hook MetricsHook) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldAudit(r) {
				next.ServeHTTP(w, r)
				return
			}

			rw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(rw, r)

			// chi RoutePattern requires running after the handler so the
			// route context is populated.
			pattern := chi.RouteContext(r.Context()).RoutePattern()
			if pattern == "" {
				pattern = r.URL.Path
			}

			actor, role := "anonymous", ""
			if c, ok := auth.ClaimsFromContext(r.Context()); ok && c != nil {
				actor = c.Sub
				role = c.Role
			}

			status := rw.Status()
			if status == 0 {
				status = http.StatusOK
			}

			ev := Event{
				ID:         uuid.New(),
				Timestamp:  time.Now().UTC(),
				Actor:      actor,
				Role:       role,
				Action:     r.Method + " " + pattern,
				Outcome:    outcomeFromStatus(status),
				StatusCode: status,
				RequestID:  middleware.GetReqID(r.Context()),
				RemoteIP:   ParseRemoteIP(r.RemoteAddr),
			}

			if sink != nil {
				// Use background-derived ctx so audit isn't cancelled when
				// the client disconnects — we still want the record.
				if err := sink.Record(r.Context(), ev); err != nil && logger != nil {
					logger.Warn().Err(err).Str("event_id", ev.ID.String()).Msg("audit record failed")
				}
			}
			if hook != nil {
				hook.IncAuditEvent(ev.Outcome)
			}
		})
	}
}

func shouldAudit(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	return strings.HasPrefix(r.URL.Path, "/api/v1/")
}

func outcomeFromStatus(s int) string {
	switch {
	case s >= 200 && s < 300:
		return OutcomeSuccess
	case s >= 400 && s < 500:
		return OutcomeDenied
	case s >= 500:
		return OutcomeError
	default:
		return OutcomeSuccess
	}
}
