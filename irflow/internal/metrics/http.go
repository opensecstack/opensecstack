package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// HTTPMiddleware returns chi-compatible middleware that records counters,
// histograms, and in-flight gauges for every request. It deliberately uses
// the chi route pattern (e.g. "/api/v1/incidents/{incidentID}") rather than
// the raw URL path so cardinality stays bounded regardless of traffic shape.
func (m *Metrics) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if m == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			// Temporary placeholder — chi fills the route pattern after routing.
			// We capture it from the RouteContext once the handler chain runs.
			next.ServeHTTP(rec, r)

			route := chi.RouteContext(r.Context()).RoutePattern()
			if route == "" {
				route = "unknown"
			}
			m.httpRequests.WithLabelValues(r.Method, route, strconv.Itoa(rec.status)).Inc()
			m.httpDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
		})
	}
}

// InFlightMiddleware increments/decrements a single global in-flight gauge
// around each request. Deliberately label-less: chi only populates the route
// pattern AFTER the handler chain runs, so any per-route gauge would always
// pair an Inc on "unknown" with a Dec on the real pattern and drift.
func (m *Metrics) InFlightMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if m == nil {
			return next
		}
		gauge := m.httpInFlight.WithLabelValues("all")
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gauge.Inc()
			defer gauge.Dec()
			next.ServeHTTP(w, r)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
