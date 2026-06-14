// Package metrics owns the OpenCSIRT Prometheus registry and the
// JSON snapshot type that the dashboard reads.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

var Registry = prometheus.NewRegistry()

var (
	IncidentsCreated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "opencsirt_incidents_created_total",
		Help: "Incidents created, labelled by source and severity.",
	}, []string{"source", "severity"})

	IncidentsClosed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "opencsirt_incidents_closed_total",
		Help: "Incidents closed.",
	}, []string{"severity"})

	AdvisoriesPublished = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "opencsirt_advisories_published_total",
		Help: "Advisories published, labelled by TLP.",
	}, []string{"tlp"})

	EscalationsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "opencsirt_escalations_sent_total",
		Help: "Cross-CSIRT escalations sent.",
	})

	CitadelEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "opencsirt_citadel_events_total",
		Help: "CITADEL outbox transitions, labelled by outcome.",
	}, []string{"outcome"})

	CitadelQueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "opencsirt_citadel_queue_depth",
		Help: "Current depth of the CITADEL retry queue.",
	})

	IOCsIngested = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "opencsirt_iocs_ingested_total",
		Help: "IOC bundles ingested, labelled by source.",
	}, []string{"source"})
)

func init() {
	Registry.MustRegister(IncidentsCreated, IncidentsClosed, AdvisoriesPublished,
		EscalationsSent, CitadelEvents, CitadelQueueDepth, IOCsIngested)
}

// Handler returns the /api/v1/metrics http handler (Prometheus exposition).
func Handler() http.Handler {
	return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{Registry: Registry})
}
