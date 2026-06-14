// Package metrics declares the Prometheus collectors exposed by
// /api/v1/metrics. The names match docs/metrics.md and
// docs/architecture.md §Observability.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// All collectors are owned by a private Registry so multiple test
// processes don't conflict on global state.
var (
	Registry = prometheus.NewRegistry()

	RulesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "openscrub_rules_total",
			Help: "Active rules currently installed, by type.",
		}, []string{"type"})

	RulesAddedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openscrub_rules_added_total",
			Help: "Total rules created since process start, by source.",
		}, []string{"type", "source"})

	RulesExpiredTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "openscrub_rules_expired_total",
			Help: "Total rules removed by TTL expiry since process start.",
		})

	RulesWithdrawnTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "openscrub_rules_withdrawn_total",
			Help: "Total rules withdrawn by operator (DELETE).",
		})

	IOCIngestedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "openscrub_ioc_ingested_total",
			Help: "Total IOCs converted to rules from external feeds.",
		})

	IOCPullsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openscrub_ioc_pulls_total",
			Help: "Total ThreatFlow pull attempts, by outcome.",
		}, []string{"outcome"})

	CitadelEmitTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openscrub_citadel_emit_total",
			Help: "Total CITADEL submissions, by outcome.",
		}, []string{"outcome"})

	DataplaneOpTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openscrub_dataplane_op_total",
			Help: "Total data-plane operations, by op + outcome.",
		}, []string{"op", "outcome"})

	// MitigationsRecoveryFailedTotal counts rules whose mitigation
	// evidence row could not be re-opened on startup. A non-zero value
	// means the watcher will not emit `openscrub.mitigation` events for
	// those rules' lifespans — operator-visible, hence a counter.
	MitigationsRecoveryFailedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "openscrub_mitigations_recovery_failed_total",
			Help: "Active rules whose mitigation row could not be re-opened on startup.",
		})
)

func init() {
	Registry.MustRegister(
		RulesTotal,
		RulesAddedTotal,
		RulesExpiredTotal,
		RulesWithdrawnTotal,
		IOCIngestedTotal,
		IOCPullsTotal,
		CitadelEmitTotal,
		DataplaneOpTotal,
		MitigationsRecoveryFailedTotal,
	)
}
