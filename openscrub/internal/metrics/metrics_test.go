package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestCollectorsRegistered verifies every exported collector was
// actually registered against the package Registry — a collector that
// exists as a var but is missing from the init() MustRegister call
// would silently never show up on /api/v1/metrics.
func TestCollectorsRegistered(t *testing.T) {
	// CounterVec/GaugeVec collectors only emit a sample (and thus only
	// show up in Gather()) once at least one label combination has been
	// touched — touch each so this test verifies registration
	// independent of test execution order.
	RulesTotal.WithLabelValues("blocklist")
	RulesAddedTotal.WithLabelValues("blocklist", "operator")
	IOCPullsTotal.WithLabelValues("success")
	CitadelEmitTotal.WithLabelValues("success")
	DataplaneOpTotal.WithLabelValues("add_blocklist", "success")

	mfs, err := Registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	want := []string{
		"openscrub_rules_total",
		"openscrub_rules_added_total",
		"openscrub_rules_expired_total",
		"openscrub_rules_withdrawn_total",
		"openscrub_ioc_ingested_total",
		"openscrub_ioc_pulls_total",
		"openscrub_citadel_emit_total",
		"openscrub_dataplane_op_total",
		"openscrub_mitigations_recovery_failed_total",
	}
	for _, w := range want {
		if !names[w] {
			t.Errorf("collector %q not registered on Registry (gathered: %v)", w, names)
		}
	}
}

// TestRegisteringTwiceFails proves the collectors in this package are
// the SAME instances registered by init() — attempting to register a
// duplicate with the same name/labels against the same registry must
// fail with an AlreadyRegisteredError.
func TestRegisteringTwiceFails(t *testing.T) {
	err := Registry.Register(RulesExpiredTotal)
	if err == nil {
		t.Fatal("expected error re-registering an already-registered collector")
	}
	if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
		t.Fatalf("expected AlreadyRegisteredError, got %T: %v", err, err)
	}
}

// TestCounterAndGaugeBehavior exercises the actual metric semantics
// (not just "it exists"): counters only go up, gauges reflect the last
// Set/value, and vectors are addressable by label.
func TestCounterAndGaugeBehavior(t *testing.T) {
	RulesExpiredTotal.Add(3)
	if got := readCounter(t, RulesExpiredTotal); got < 3 {
		t.Fatalf("RulesExpiredTotal after Add(3) = %v, want >= 3", got)
	}

	RulesTotal.WithLabelValues("blocklist").Set(7)
	if got := readGauge(t, RulesTotal.WithLabelValues("blocklist")); got != 7 {
		t.Fatalf("RulesTotal{type=blocklist} = %v, want 7", got)
	}
	RulesTotal.WithLabelValues("blocklist").Set(2)
	if got := readGauge(t, RulesTotal.WithLabelValues("blocklist")); got != 2 {
		t.Fatalf("RulesTotal{type=blocklist} after second Set = %v, want 2 (last write wins)", got)
	}

	IOCPullsTotal.WithLabelValues("success").Inc()
	IOCPullsTotal.WithLabelValues("success").Inc()
	IOCPullsTotal.WithLabelValues("failure").Inc()
	if got := readCounterVec(t, IOCPullsTotal, "success"); got < 2 {
		t.Fatalf("IOCPullsTotal{outcome=success} = %v, want >= 2", got)
	}
	if got := readCounterVec(t, IOCPullsTotal, "failure"); got < 1 {
		t.Fatalf("IOCPullsTotal{outcome=failure} = %v, want >= 1", got)
	}
}

func readCounter(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("write counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

func readGauge(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("write gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}

func readCounterVec(t *testing.T, cv *prometheus.CounterVec, label string) float64 {
	t.Helper()
	return readCounter(t, cv.WithLabelValues(label))
}
