// VG-006 IOC store + community-feed sync metrics.
//
// Kept in a separate file so the puller can pull just the IOC section
// without dragging the full Registry surface into its tests.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// IOCMetrics is the subset of collectors the puller + store touch.
// Defined as an interface so tests can pass a no-op recorder.
type IOCMetrics interface {
	IncPull(source, result string)
	IncFailure(source string)
	SetActive(n float64)
}

// iocCollectors bundles the three collectors together so a single
// constructor wires them onto the shared registry.
type iocCollectors struct {
	pulls    *prometheus.CounterVec
	failures *prometheus.CounterVec
	active   prometheus.Gauge
}

func (c *iocCollectors) IncPull(source, result string) {
	c.pulls.WithLabelValues(source, result).Inc()
}

func (c *iocCollectors) IncFailure(source string) {
	c.failures.WithLabelValues(source).Inc()
}

func (c *iocCollectors) SetActive(n float64) { c.active.Set(n) }

// NewIOCMetricsAdapter registers the IOC collectors on the supplied
// registry and returns an adapter satisfying IOCMetrics. Idempotent
// against repeated calls only when the underlying registry tolerates
// duplicate registration — production wires this exactly once.
func NewIOCMetricsAdapter(r *Registry) IOCMetrics {
	c := &iocCollectors{
		pulls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vertguard_ioc_pull_total",
			Help: "IOC community-feed pulls by source and result (ok|fail|skipped).",
		}, []string{"source", "result"}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vertguard_ioc_pull_failures_total",
			Help: "IOC pulls that failed before producing any rows.",
		}, []string{"source"}),
		active: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vertguard_ioc_active_total",
			Help: "Active (non-expired) IOCs in the store after the last sweep.",
		}),
	}
	if r != nil && r.prom != nil {
		r.prom.MustRegister(c.pulls, c.failures, c.active)
	}
	return c
}

// NopIOCMetrics is the zero-value, no-op adapter used by tests and
// when the puller runs without a registry.
type NopIOCMetrics struct{}

func (NopIOCMetrics) IncPull(string, string) {}
func (NopIOCMetrics) IncFailure(string)      {}
func (NopIOCMetrics) SetActive(float64)      {}
