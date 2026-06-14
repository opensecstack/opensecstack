package middleware

import (
	"expvar"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// MetricsCollector tracks HTTP request metrics using expvar (stdlib).
// Exposes counts and latency histograms at GET /metrics (JSON).
type MetricsCollector struct {
	mu            sync.Mutex
	requestsTotal *expvar.Map  // keyed by "method:status"
	requestsDur   *expvar.Map  // keyed by "method:path" — cumulative ms
	activeReqs    *expvar.Int
	errorsTotal   *expvar.Int
}

// NewMetricsCollector registers expvar metrics and returns a collector.
// Call once at server startup; subsequent calls return existing vars.
func NewMetricsCollector() *MetricsCollector {
	// expvar.NewMap panics on duplicate registration — use Get+cast or recover
	getOrNewMap := func(name string) *expvar.Map {
		if v := expvar.Get(name); v != nil {
			if m, ok := v.(*expvar.Map); ok {
				return m
			}
		}
		return expvar.NewMap(name)
	}
	getOrNewInt := func(name string) *expvar.Int {
		if v := expvar.Get(name); v != nil {
			if i, ok := v.(*expvar.Int); ok {
				return i
			}
		}
		return expvar.NewInt(name)
	}

	return &MetricsCollector{
		requestsTotal: getOrNewMap("http_requests_total"),
		requestsDur:   getOrNewMap("http_request_duration_ms"),
		activeReqs:    getOrNewInt("http_active_requests"),
		errorsTotal:   getOrNewInt("http_errors_total"),
	}
}

// Middleware returns an http.Handler middleware that records metrics.
func (mc *MetricsCollector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mc.activeReqs.Add(1)
		defer mc.activeReqs.Add(-1)

		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		durationMs := time.Since(start).Milliseconds()

		key := r.Method + ":" + strconv.Itoa(rw.status)
		mc.requestsTotal.Add(key, 1)

		durKey := r.Method + ":" + r.URL.Path
		mc.requestsDur.Add(durKey, durationMs)

		if rw.status >= 500 {
			mc.errorsTotal.Add(1)
		}
	})
}

// Handler returns an http.HandlerFunc that serves the expvar metrics as JSON.
// Mount this at GET /metrics (or GET /debug/vars — they are equivalent).
func (mc *MetricsCollector) Handler() http.HandlerFunc {
	return expvar.Handler().ServeHTTP
}

// statusRecorder wraps http.ResponseWriter to capture the response status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
