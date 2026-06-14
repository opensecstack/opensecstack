// Package metrics defines CyberPath's Prometheus collectors.
//
// Initial v0.0.1 catalogue. Additional collectors land as modules come
// online (lab runtime, content engine, certifications).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Registry bundles the CyberPath-specific collectors.
type Registry struct {
	prom *prometheus.Registry

	HTTPRequestsTotal      *prometheus.CounterVec
	HTTPRequestDuration    *prometheus.HistogramVec
	CompletionsTotal       *prometheus.CounterVec
	LabSessionsActive      prometheus.Gauge
	CitadelSubmissionsTotal *prometheus.CounterVec

	// Outbox / CITADEL worker collectors.
	//
	// OutboxEnqueuedTotal — counter of rows added to the outbox by the
	// API handlers (labelled by destination + event_type).
	OutboxEnqueuedTotal *prometheus.CounterVec
	// OutboxDeliveredTotal — counter of rows the worker successfully
	// shipped (CITADEL 2xx or webhook 2xx).
	OutboxDeliveredTotal *prometheus.CounterVec
	// OutboxFailedTotal — counter of failed delivery attempts. The
	// "retryable" label is "true" if the row will be re-attempted,
	// "false" if it was flipped straight to dlq (4xx schema error).
	OutboxFailedTotal *prometheus.CounterVec
	// OutboxDLQDepth — current number of rows in status='dlq'. The
	// worker bumps this gauge whenever it flips a row into dlq; an
	// out-of-band reconciler may also adjust it.
	OutboxDLQDepth prometheus.Gauge
	// OutboxInFlight — number of rows currently being dispatched by
	// any worker goroutine (in-process gauge, not a DB-level count).
	OutboxInFlight prometheus.Gauge
	// OutboxDeliveryDuration — histogram of dispatch wall-clock time
	// per row, labelled by destination + event_type. Default buckets.
	OutboxDeliveryDuration *prometheus.HistogramVec
}

// New registers all collectors on a fresh Prometheus registry.
func New() *Registry {
	reg := prometheus.NewRegistry()
	r := &Registry{prom: reg}

	r.HTTPRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cyberpath_http_requests_total",
		Help: "HTTP requests by method, path template, and response status.",
	}, []string{"method", "path", "status"})

	r.HTTPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "cyberpath_http_request_duration_seconds",
		Help:    "HTTP request latency.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	r.CompletionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cyberpath_completions_total",
		Help: "Lesson / module / track completions by kind.",
	}, []string{"kind"})

	r.LabSessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cyberpath_lab_sessions_active",
		Help: "Currently running lab sandbox sessions.",
	})

	r.CitadelSubmissionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cyberpath_citadel_submissions_total",
		Help: "CITADEL completion event submissions by result.",
	}, []string{"result"})

	r.OutboxEnqueuedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cyberpath_outbox_enqueued_total",
		Help: "Outbox rows enqueued by destination and event_type.",
	}, []string{"destination", "event_type"})

	r.OutboxDeliveredTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cyberpath_outbox_delivered_total",
		Help: "Outbox rows delivered successfully by destination and event_type.",
	}, []string{"destination", "event_type"})

	r.OutboxFailedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cyberpath_outbox_failed_total",
		Help: "Outbox delivery failures by destination, event_type and whether the failure is retryable.",
	}, []string{"destination", "event_type", "retryable"})

	r.OutboxDLQDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cyberpath_outbox_dlq_depth",
		Help: "Current number of outbox rows in dead-letter queue (status='dlq').",
	})

	r.OutboxInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cyberpath_outbox_in_flight",
		Help: "In-process count of outbox rows currently being dispatched.",
	})

	r.OutboxDeliveryDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "cyberpath_outbox_delivery_duration_seconds",
		Help:    "Wall-clock latency of a single outbox row dispatch.",
		Buckets: prometheus.DefBuckets,
	}, []string{"destination", "event_type"})

	reg.MustRegister(
		r.HTTPRequestsTotal,
		r.HTTPRequestDuration,
		r.CompletionsTotal,
		r.LabSessionsActive,
		r.CitadelSubmissionsTotal,
		r.OutboxEnqueuedTotal,
		r.OutboxDeliveredTotal,
		r.OutboxFailedTotal,
		r.OutboxDLQDepth,
		r.OutboxInFlight,
		r.OutboxDeliveryDuration,
	)
	return r
}

// Prometheus returns the underlying registry for handler use.
func (r *Registry) Prometheus() *prometheus.Registry { return r.prom }
