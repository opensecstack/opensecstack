// Package metrics exposes Prometheus counters, gauges, and histograms for
// every IRFlow subsystem and provides the /metrics HTTP handler.
//
// Metrics are owned by a per-instance Registry so tests can create isolated
// Metrics objects without tripping on "duplicate collector registration"
// from the global default registry.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is the full collector surface IRFlow exports.
type Metrics struct {
	reg *prometheus.Registry

	httpRequests  *prometheus.CounterVec
	httpDuration  *prometheus.HistogramVec
	httpInFlight  *prometheus.GaugeVec
	incidents     *prometheus.CounterVec
	actions       *prometheus.CounterVec
	playbookRuns  *prometheus.CounterVec
	playbookSteps *prometheus.CounterVec
	webhooks      *prometheus.CounterVec
	governance    *prometheus.CounterVec
	dbConns       *prometheus.GaugeVec
}

// New creates a Metrics bound to a fresh Registry. Passing a non-nil registry
// lets callers share collectors across packages in tests.
func New(reg *prometheus.Registry) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	m := &Metrics{
		reg: reg,
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "irflow",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests by method, route, and status.",
		}, []string{"method", "route", "status"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "irflow",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request latency in seconds.",
			Buckets:   prometheus.ExponentialBuckets(0.005, 2, 12), // 5ms → ~10s
		}, []string{"method", "route"}),
		httpInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "irflow",
			Subsystem: "http",
			Name:      "requests_in_flight",
			Help:      "Current in-flight HTTP requests by route.",
		}, []string{"route"}),
		incidents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "irflow",
			Name:      "incidents_created_total",
			Help:      "Incidents created, labelled by severity and source.",
		}, []string{"severity", "source"}),
		actions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "irflow",
			Name:      "actions_submitted_total",
			Help:      "Governed incident actions submitted, labelled by MARSHAL outcome (EXECUTE/REFUSE/HARD_STOP/LOCAL).",
		}, []string{"outcome"}),
		playbookRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "irflow",
			Name:      "playbook_executions_total",
			Help:      "Playbook executions completed, labelled by outcome.",
		}, []string{"outcome"}),
		playbookSteps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "irflow",
			Name:      "playbook_steps_total",
			Help:      "Playbook step executions, labelled by step type and result.",
		}, []string{"step_type", "result"}),
		webhooks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "irflow",
			Name:      "webhooks_received_total",
			Help:      "Inbound webhook events, labelled by source and result (accepted/rejected_signature/rejected_payload/error).",
		}, []string{"source", "result"}),
		governance: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "irflow",
			Name:      "governance_calls_total",
			Help:      "Outbound governance calls, labelled by target (citadel_marshal/citadel_worm/nis2) and result (success/failure).",
		}, []string{"target", "result"}),
		dbConns: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "irflow",
			Name:      "db_pool_connections",
			Help:      "PostgreSQL connection pool stats.",
		}, []string{"state"}), // acquired | idle | max
	}

	reg.MustRegister(
		m.httpRequests, m.httpDuration, m.httpInFlight,
		m.incidents, m.actions,
		m.playbookRuns, m.playbookSteps,
		m.webhooks, m.governance, m.dbConns,
	)
	// Go runtime + process collectors so ops have standard baseline metrics.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return m
}

// Handler returns the http.Handler for /metrics scraping.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{
		Registry: m.reg,
	})
}

// Registry exposes the underlying registry so callers can register
// additional collectors (e.g. a pgxpool stats collector).
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// ---------------------------------------------------------------------------
// Domain hooks — callable from services. Nil-safe so services can wire
// metrics as an optional dependency and tests can use nil.
// ---------------------------------------------------------------------------

// IncidentCreated records a new incident by severity and source.
func (m *Metrics) IncidentCreated(severity, source string) {
	if m == nil {
		return
	}
	m.incidents.WithLabelValues(severity, source).Inc()
}

// ActionSubmitted records a governed action outcome.
// outcome values: "EXECUTE" | "REFUSE" | "HARD_STOP" | "LOCAL".
func (m *Metrics) ActionSubmitted(outcome string) {
	if m == nil {
		return
	}
	m.actions.WithLabelValues(outcome).Inc()
}

// PlaybookExecuted records a playbook execution outcome.
// outcome values: "completed" | "failed" | "cancelled".
func (m *Metrics) PlaybookExecuted(outcome string) {
	if m == nil {
		return
	}
	m.playbookRuns.WithLabelValues(outcome).Inc()
}

// PlaybookStep records a single step's execution.
// result values: "success" | "failed" | "skipped".
func (m *Metrics) PlaybookStep(stepType, result string) {
	if m == nil {
		return
	}
	m.playbookSteps.WithLabelValues(stepType, result).Inc()
}

// WebhookReceived records a webhook outcome.
// source: apiguard | citadel | threatflow.
// result: accepted | rejected_signature | rejected_payload | error.
func (m *Metrics) WebhookReceived(source, result string) {
	if m == nil {
		return
	}
	m.webhooks.WithLabelValues(source, result).Inc()
}

// GovernanceCall records the result of an outbound governance call.
// target: citadel_marshal | citadel_worm | nis2.
// result: success | failure.
func (m *Metrics) GovernanceCall(target, result string) {
	if m == nil {
		return
	}
	m.governance.WithLabelValues(target, result).Inc()
}

// SetDBPoolStats updates the DB pool gauges. Call periodically from a
// background ticker in the serve command.
func (m *Metrics) SetDBPoolStats(acquired, idle, max int32) {
	if m == nil {
		return
	}
	m.dbConns.WithLabelValues("acquired").Set(float64(acquired))
	m.dbConns.WithLabelValues("idle").Set(float64(idle))
	m.dbConns.WithLabelValues("max").Set(float64(max))
}
