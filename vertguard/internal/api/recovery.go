package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/audit"
)

// RecoveryMiddleware recovers panics and emits an audit event so post-
// mortem queries can find them. chi's stock Recoverer logs but never
// reaches the audit pipeline, which would let a panic in a state-changing
// handler escape the immutable record.
func RecoveryMiddleware(sink audit.Sink, logger *zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rvr := recover()
				if rvr == nil {
					return
				}
				// http.ErrAbortHandler is the documented escape hatch for
				// callers that want the connection torn down without
				// logging — preserve that behaviour.
				if rvr == http.ErrAbortHandler {
					panic(rvr)
				}

				stack := debug.Stack()

				if logger != nil {
					logger.Error().
						Interface("panic", rvr).
						Bytes("stack", stack).
						Str("method", r.Method).
						Str("path", r.URL.Path).
						Str("request_id", middleware.GetReqID(r.Context())).
						Msg("panic recovered")
				}

				// Best-effort response: a panic may have already written
				// headers, in which case WriteHeader is a no-op.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "internal server error",
					"code":  "panic_recovered",
				})

				if sink != nil {
					meta, _ := json.Marshal(map[string]string{
						"panic": fmt.Sprint(rvr),
						"stack": string(stack),
					})
					ev := audit.Event{
						ID:         uuid.New(),
						Timestamp:  time.Now().UTC(),
						Actor:      "system",
						Action:     "PANIC " + r.Method + " " + r.URL.Path,
						Outcome:    audit.OutcomeError,
						StatusCode: http.StatusInternalServerError,
						RequestID:  middleware.GetReqID(r.Context()),
						RemoteIP:   audit.ParseRemoteIP(r.RemoteAddr),
						Metadata:   meta,
					}
					if err := sink.Record(r.Context(), ev); err != nil && logger != nil {
						logger.Warn().Err(err).Str("event_id", ev.ID.String()).Msg("audit record failed (panic)")
					}
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
