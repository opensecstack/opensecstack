package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNew_RegistersAllCollectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	// Drive each counter once so it shows up in Gather.
	m.IncidentCreated("P1", "apiguard")
	m.ActionSubmitted("EXECUTE")
	m.PlaybookExecuted("completed")
	m.PlaybookStep("action", "success")
	m.WebhookReceived("citadel", "accepted")
	m.GovernanceCall("citadel_marshal", "success")
	m.SetDBPoolStats(3, 7, 20)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	want := []string{
		"irflow_incidents_created_total",
		"irflow_actions_submitted_total",
		"irflow_playbook_executions_total",
		"irflow_playbook_steps_total",
		"irflow_webhooks_received_total",
		"irflow_governance_calls_total",
		"irflow_db_pool_connections",
	}
	got := map[string]bool{}
	for _, f := range families {
		got[f.GetName()] = true
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("metric %s was not gathered", name)
		}
	}
}

func TestIncidentCreated_IncrementsByLabel(t *testing.T) {
	m := New(prometheus.NewRegistry())
	m.IncidentCreated("P1", "apiguard")
	m.IncidentCreated("P1", "apiguard")
	m.IncidentCreated("P2", "citadel")

	if got := testutil.ToFloat64(m.incidents.WithLabelValues("P1", "apiguard")); got != 2 {
		t.Errorf("P1/apiguard = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.incidents.WithLabelValues("P2", "citadel")); got != 1 {
		t.Errorf("P2/citadel = %v, want 1", got)
	}
}

func TestNilReceiverIsNoOp(t *testing.T) {
	// All hooks must be safe on a nil *Metrics (services wire this as an
	// optional dependency).
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil receiver panicked: %v", r)
		}
	}()
	var m *Metrics
	m.IncidentCreated("P1", "x")
	m.ActionSubmitted("EXECUTE")
	m.PlaybookExecuted("completed")
	m.PlaybookStep("action", "success")
	m.WebhookReceived("x", "accepted")
	m.GovernanceCall("x", "success")
	m.SetDBPoolStats(0, 0, 0)
}

func TestHandler_ServesOpenMetricsText(t *testing.T) {
	m := New(prometheus.NewRegistry())
	m.IncidentCreated("P1", "manual")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "irflow_incidents_created_total") {
		t.Errorf("body missing metric name; got:\n%s", body)
	}
}

func TestHTTPMiddleware_CountsRequestsPerRoutePattern(t *testing.T) {
	m := New(prometheus.NewRegistry())
	r := chi.NewRouter()
	r.Use(m.HTTPMiddleware())
	r.Get("/api/v1/incidents/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Two requests with different IDs — should both count against the same
	// pattern label, not distinct full paths.
	for _, id := range []string{"inc-1", "inc-2"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/"+id, nil)
		r.ServeHTTP(httptest.NewRecorder(), req)
	}

	got := testutil.ToFloat64(m.httpRequests.WithLabelValues("GET", "/api/v1/incidents/{id}", "200"))
	if got != 2 {
		t.Errorf("counter = %v, want 2 (both IDs should hash to same pattern)", got)
	}
}

func TestHTTPMiddleware_RecordsStatus(t *testing.T) {
	m := New(prometheus.NewRegistry())
	r := chi.NewRouter()
	r.Use(m.HTTPMiddleware())
	r.Get("/boom", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})

	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	got := testutil.ToFloat64(m.httpRequests.WithLabelValues("GET", "/boom", "502"))
	if got != 1 {
		t.Errorf("counter = %v, want 1 for status 502", got)
	}
}

func TestNilMiddleware_IsPassthrough(t *testing.T) {
	// A nil *Metrics must return passthrough middleware so tests can pass
	// zero values without crashing.
	var m *Metrics
	h := m.HTTPMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", rec.Code)
	}
}
