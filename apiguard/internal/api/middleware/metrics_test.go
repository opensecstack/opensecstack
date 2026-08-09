package middleware

import (
	"expvar"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// newTestCollector returns a fresh MetricsCollector. Because expvar variables
// are process-global we use unique names per test via the get-or-create logic
// already built into NewMetricsCollector; calling it multiple times within the
// same test binary is safe.
func newTestCollector() *MetricsCollector {
	return NewMetricsCollector()
}

// TestMetricsCollector_Handler verifies that Handler() serves the expvar
// registry as JSON, including the metrics this collector itself registers.
func TestMetricsCollector_Handler(t *testing.T) {
	mc := newTestCollector()
	// Exercise the middleware once so http_requests_total has an entry.
	mc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	mc.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "http_requests_total") {
		t.Errorf("body does not contain http_requests_total: %s", body)
	}
}

// getExpvarInt retrieves the current value of a named expvar.Int. Returns 0
// when the variable has not been registered yet.
func getExpvarInt(name string) int64 {
	v := expvar.Get(name)
	if v == nil {
		return 0
	}
	if i, ok := v.(*expvar.Int); ok {
		return i.Value()
	}
	return 0
}

// getExpvarMapKey retrieves the int64 stored under key in the named expvar.Map.
// Returns 0 when the variable or key is absent.
func getExpvarMapKey(mapName, key string) int64 {
	v := expvar.Get(mapName)
	if v == nil {
		return 0
	}
	m, ok := v.(*expvar.Map)
	if !ok {
		return 0
	}
	kv := m.Get(key)
	if kv == nil {
		return 0
	}
	if i, ok := kv.(*expvar.Int); ok {
		return i.Value()
	}
	return 0
}

// TestMetricsMiddleware_CallsNext verifies the middleware does not block the
// downstream handler.
func TestMetricsMiddleware_CallsNext(t *testing.T) {
	mc := newTestCollector()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	mc.Middleware(next).ServeHTTP(rr, req)

	if !called {
		t.Error("downstream handler was not called by Metrics middleware")
	}
}

// TestMetricsMiddleware_PassesThrough200 verifies a 200 response is not
// altered by the middleware.
func TestMetricsMiddleware_PassesThrough200(t *testing.T) {
	mc := newTestCollector()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	rr := httptest.NewRecorder()
	mc.Middleware(makeStatusHandler(http.StatusOK)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

// TestMetricsMiddleware_PassesThrough404 confirms 404 is forwarded unchanged.
func TestMetricsMiddleware_PassesThrough404(t *testing.T) {
	mc := newTestCollector()
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rr := httptest.NewRecorder()
	mc.Middleware(makeStatusHandler(http.StatusNotFound)).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// TestMetricsMiddleware_PassesThrough500 confirms 500 is forwarded unchanged.
func TestMetricsMiddleware_PassesThrough500(t *testing.T) {
	mc := newTestCollector()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	rr := httptest.NewRecorder()
	mc.Middleware(makeStatusHandler(http.StatusInternalServerError)).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

// TestMetricsMiddleware_RequestCountIncrements verifies that http_requests_total
// increases after each request.
func TestMetricsMiddleware_RequestCountIncrements(t *testing.T) {
	mc := newTestCollector()

	key := "GET:200"
	before := getExpvarMapKey("http_requests_total", key)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/count", nil)
		rr := httptest.NewRecorder()
		mc.Middleware(makeStatusHandler(http.StatusOK)).ServeHTTP(rr, req)
	}

	after := getExpvarMapKey("http_requests_total", key)
	if after-before != 3 {
		t.Errorf("http_requests_total[%s] delta = %d, want 3", key, after-before)
	}
}

// TestMetricsMiddleware_ErrorsTotalIncrements verifies that http_errors_total
// is incremented for 5xx responses.
func TestMetricsMiddleware_ErrorsTotalIncrements(t *testing.T) {
	mc := newTestCollector()

	before := getExpvarInt("http_errors_total")

	req := httptest.NewRequest(http.MethodGet, "/err", nil)
	rr := httptest.NewRecorder()
	mc.Middleware(makeStatusHandler(http.StatusInternalServerError)).ServeHTTP(rr, req)

	after := getExpvarInt("http_errors_total")
	if after <= before {
		t.Errorf("http_errors_total did not increment after 500 response (before=%d after=%d)", before, after)
	}
}

// TestMetricsMiddleware_ErrorsNotIncrementedFor4xx verifies that 4xx responses
// do NOT increment http_errors_total.
func TestMetricsMiddleware_ErrorsNotIncrementedFor4xx(t *testing.T) {
	mc := newTestCollector()

	before := getExpvarInt("http_errors_total")

	req := httptest.NewRequest(http.MethodGet, "/notfound", nil)
	rr := httptest.NewRecorder()
	mc.Middleware(makeStatusHandler(http.StatusNotFound)).ServeHTTP(rr, req)

	after := getExpvarInt("http_errors_total")
	if after != before {
		t.Errorf("http_errors_total should not increment for 404 (before=%d after=%d)", before, after)
	}
}

// TestMetricsMiddleware_ActiveRequestsTracked verifies that http_active_requests
// goes up by 1 while a handler is executing and returns to the previous value
// afterwards.
func TestMetricsMiddleware_ActiveRequestsTracked(t *testing.T) {
	mc := newTestCollector()

	baseline := getExpvarInt("http_active_requests")

	var (
		mu         sync.Mutex
		activeSnap int64
		wg         sync.WaitGroup
	)

	// A handler that captures active_requests mid-flight.
	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		activeSnap = getExpvarInt("http_active_requests")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodGet, "/active", nil)
		rr := httptest.NewRecorder()
		mc.Middleware(capture).ServeHTTP(rr, req)
	}()
	wg.Wait()

	// While handling, active count must be baseline+1.
	mu.Lock()
	snap := activeSnap
	mu.Unlock()

	if snap != baseline+1 {
		t.Errorf("http_active_requests during handler = %d, want %d", snap, baseline+1)
	}

	// After handling, active count must return to baseline.
	after := getExpvarInt("http_active_requests")
	if after != baseline {
		t.Errorf("http_active_requests after handler = %d, want %d", after, baseline)
	}
}

// TestMetricsMiddleware_DurationRecorded verifies that at least one entry is
// written to http_request_duration_ms after a request.
func TestMetricsMiddleware_DurationRecorded(t *testing.T) {
	mc := newTestCollector()

	const path = "/duration-probe"
	durKey := "GET:" + path

	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	mc.Middleware(makeStatusHandler(http.StatusOK)).ServeHTTP(rr, req)

	// Duration is cumulative milliseconds; after one request the value must be
	// present (>= 0 is sufficient — the request may complete in <1 ms).
	v := expvar.Get("http_request_duration_ms")
	if v == nil {
		t.Fatal("http_request_duration_ms expvar not registered")
	}
	m, ok := v.(*expvar.Map)
	if !ok {
		t.Fatal("http_request_duration_ms is not an *expvar.Map")
	}
	if m.Get(durKey) == nil {
		t.Errorf("http_request_duration_ms[%s] not recorded after request", durKey)
	}
}

// TestMetricsMiddleware_NewCollectorIdempotent verifies that calling
// NewMetricsCollector more than once does not panic (expvar get-or-create).
func TestMetricsMiddleware_NewCollectorIdempotent(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewMetricsCollector panicked on second call: %v", r)
		}
	}()
	_ = NewMetricsCollector()
	_ = NewMetricsCollector()
}
