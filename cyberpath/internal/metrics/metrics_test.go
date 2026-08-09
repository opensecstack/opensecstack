package metrics

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func TestNew_RegistersAllCollectorsWithoutPanic(t *testing.T) {
	// prometheus.MustRegister panics on duplicate metric names, so a
	// clean New() call proves every collector was registered exactly once
	// with a unique name.
	r := New()
	if r == nil {
		t.Fatalf("New: got nil registry")
	}
	if r.Prometheus() == nil {
		t.Fatalf("Prometheus(): got nil underlying *prometheus.Registry")
	}
}

func TestNew_ReturnsIndependentRegistries(t *testing.T) {
	// Constructing two registries must not panic (each uses its own fresh
	// prometheus.Registry, so metric names can safely repeat across them).
	r1 := New()
	r2 := New()
	if r1.Prometheus() == r2.Prometheus() {
		t.Fatalf("New: two calls returned the same underlying registry")
	}
}

func TestRegistry_CountersRecordObservations(t *testing.T) {
	r := New()

	r.HTTPRequestsTotal.WithLabelValues("GET", "/api/v1/health", "200").Inc()
	r.CompletionsTotal.WithLabelValues("lesson").Add(3)
	r.LabSessionsActive.Set(5)
	r.CitadelSubmissionsTotal.WithLabelValues("ok").Inc()

	families, err := r.Prometheus().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	got := metricValue(t, families, "cyberpath_http_requests_total", map[string]string{
		"method": "GET", "path": "/api/v1/health", "status": "200",
	})
	if got != 1 {
		t.Fatalf("cyberpath_http_requests_total: got %v, want 1", got)
	}

	gotCompletions := metricValue(t, families, "cyberpath_completions_total", map[string]string{"kind": "lesson"})
	if gotCompletions != 3 {
		t.Fatalf("cyberpath_completions_total: got %v, want 3", gotCompletions)
	}

	gotGauge := metricValue(t, families, "cyberpath_lab_sessions_active", nil)
	if gotGauge != 5 {
		t.Fatalf("cyberpath_lab_sessions_active: got %v, want 5", gotGauge)
	}
}

// metricValue searches gathered metric families for name with matching
// labels and returns its counter/gauge value. Fails the test if not found.
func metricValue(t *testing.T, families []*dto.MetricFamily, name string, labels map[string]string) float64 {
	t.Helper()
	for _, fam := range families {
		if fam.GetName() != name {
			continue
		}
		for _, m := range fam.GetMetric() {
			if !labelsMatch(m.GetLabel(), labels) {
				continue
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue()
			}
			if g := m.GetGauge(); g != nil {
				return g.GetValue()
			}
		}
	}
	t.Fatalf("metric %q with labels %v not found in gathered families", name, labels)
	return 0
}

func labelsMatch(got []*dto.LabelPair, want map[string]string) bool {
	if len(want) == 0 {
		return true
	}
	m := make(map[string]string, len(got))
	for _, lp := range got {
		m[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if m[k] != v {
			return false
		}
	}
	return true
}
