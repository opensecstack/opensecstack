// Package metrics defines the VertGuard Prometheus collectors.
//
// STATUS: Phase 4.1 initial catalogue. Additional collectors land as
// modules come online.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Registry bundles the VertGuard-specific collectors.
type Registry struct {
	prom *prometheus.Registry

	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec

	PromptScansTotal    *prometheus.CounterVec
	PatternMatchesTotal *prometheus.CounterVec
	PromptScanLatency   *prometheus.HistogramVec
	// PromptMLErrorsTotal counts ML-enricher failures observed by the
	// prompt scanner, labelled by backend version + low-cardinality
	// error class. Soft-failures: the scanner still degrades to the
	// regex verdict — this is for observability only.
	PromptMLErrorsTotal *prometheus.CounterVec

	PhishingScansTotal            *prometheus.CounterVec
	PhishingIndicatorMatchesTotal *prometheus.CounterVec
	PhishingScanLatency           *prometheus.HistogramVec

	ThreatFeedIOCsTotal     *prometheus.GaugeVec
	ThreatFeedPushTotal     *prometheus.CounterVec
	ThreatFeedStalenessSecs *prometheus.GaugeVec

	CitadelCallsTotal  *prometheus.CounterVec
	CitadelLatencySecs *prometheus.HistogramVec
	WORMEmitTotal      *prometheus.CounterVec
	CitadelQueueDepth  prometheus.Gauge

	AuditEventsTotal *prometheus.CounterVec

	RateLimitedTotal *prometheus.CounterVec

	JWTSecretUsedTotal *prometheus.CounterVec

	AdminSyncTotal *prometheus.CounterVec

	DenylistSize      prometheus.Gauge
	DenylistHitsTotal *prometheus.CounterVec

	RateLimitOverridesActive  prometheus.Gauge
	RateLimitOverrideHitTotal *prometheus.CounterVec

	// ML enricher (Phase 4.2+).
	MLCallsTotal       *prometheus.CounterVec
	MLLatencySeconds   *prometheus.HistogramVec
	MLBreakerOpenTotal *prometheus.CounterVec

	// Module 6 — Identity Verification (rule-based v1).
	IdentityScansTotal            *prometheus.CounterVec
	IdentityIndicatorMatchesTotal *prometheus.CounterVec
	IdentityScanLatency           *prometheus.HistogramVec
	IdentityReplayHitsTotal       prometheus.Counter

	// VG-015 — outbound webhook dispatcher.
	Webhook *WebhookMetrics
}

// New registers all collectors on a fresh Prometheus registry.
func New() *Registry {
	reg := prometheus.NewRegistry()
	r := &Registry{prom: reg}

	r.HTTPRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_http_requests_total",
		Help: "HTTP requests by method, path template, and response status.",
	}, []string{"method", "path", "status"})

	r.HTTPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vertguard_http_request_duration_seconds",
		Help:    "HTTP request latency.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	r.PromptScansTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_prompt_scans_total",
		Help: "Prompt scans by final classification.",
	}, []string{"classification"})

	r.PatternMatchesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_pattern_matches_total",
		Help: "Per-pattern match counter.",
	}, []string{"pattern_id", "category"})

	r.PromptScanLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vertguard_prompt_scan_latency_seconds",
		Help:    "Prompt scan latency.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
	}, []string{"classification"})

	r.PromptMLErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_prompt_ml_errors_total",
		Help: "ML-enricher failures observed by the prompt scanner (soft-fail; regex verdict still applied).",
	}, []string{"backend", "error_class"})

	r.ThreatFeedIOCsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vertguard_threatfeed_iocs_total",
		Help: "AI-IOC count by source and ATLAS technique.",
	}, []string{"source", "atlas_technique"})

	r.ThreatFeedPushTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_threatfeed_push_total",
		Help: "ThreatFlow push outcomes.",
	}, []string{"target", "result"})

	r.ThreatFeedStalenessSecs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vertguard_threatfeed_staleness_seconds",
		Help: "Seconds since the last successful sync per source.",
	}, []string{"source"})

	r.CitadelCallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_citadel_calls_total",
		Help: "CITADEL outbound call outcomes.",
	}, []string{"target", "result"})

	r.CitadelLatencySecs = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vertguard_citadel_latency_seconds",
		Help:    "CITADEL outbound call latency.",
		Buckets: prometheus.DefBuckets,
	}, []string{"target"})

	r.WORMEmitTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_worm_emit_total",
		Help: "WORM emissions by event type and result.",
	}, []string{"event_type", "result"})

	r.CitadelQueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vertguard_citadel_queue_depth",
		Help: "Local queue depth when CITADEL is unreachable.",
	})

	r.PhishingScansTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_phishing_scans_total",
		Help: "Phishing scans by final classification.",
	}, []string{"classification"})

	r.PhishingIndicatorMatchesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_phishing_indicator_matches_total",
		Help: "Per-indicator phishing match counter.",
	}, []string{"indicator_id", "category"})

	r.PhishingScanLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vertguard_phishing_scan_latency_seconds",
		Help:    "Phishing scan latency.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
	}, []string{"classification"})

	r.AuditEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_audit_events_total",
		Help: "Audit events recorded by outcome.",
	}, []string{"outcome"})

	r.RateLimitedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_rate_limited_total",
		Help: "Requests rejected by the per-key rate limiter.",
	}, []string{"scope"})

	r.JWTSecretUsedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_jwt_secret_used_total",
		Help: "JWT verifications by secret slot used to validate the signature (primary|next|previous).",
	}, []string{"slot"})

	// Operator-triggered admin actions: ATLAS sync + pattern reload.
	// `kind` is "atlas" or "patterns"; `result` is "ok" or "fail".
	r.AdminSyncTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_admin_sync_total",
		Help: "Operator-triggered admin sync/reload outcomes.",
	}, []string{"kind", "result"})

	r.DenylistSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vertguard_denylist_size",
		Help: "Current size of the in-memory JWT denylist snapshot.",
	})

	r.DenylistHitsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_denylist_hits_total",
		Help: "JWT denylist matches by kind (jti|sub).",
	}, []string{"kind"})

	r.RateLimitOverridesActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "vertguard_ratelimit_overrides_active",
		Help: "Active per-key rate-limit overrides loaded in the limiter snapshot.",
	})

	r.RateLimitOverrideHitTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_ratelimit_override_hits_total",
		Help: "Requests checked against an override-derived bucket, by kind and decision.",
	}, []string{"kind", "decision"})

	// ML enricher: rpc ∈ score_prompt|score_phishing|model_info,
	// result ∈ ok|fail|breaker_open|timeout.
	r.MLCallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_ml_calls_total",
		Help: "ML inference RPC outcomes.",
	}, []string{"rpc", "result"})

	r.MLLatencySeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vertguard_ml_latency_seconds",
		Help:    "ML inference RPC latency.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	}, []string{"rpc"})

	r.MLBreakerOpenTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_ml_breaker_open_total",
		Help: "ML breaker short-circuits per RPC.",
	}, []string{"rpc"})

	r.IdentityScansTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_identity_scans_total",
		Help: "Identity verifications by final classification.",
	}, []string{"classification"})

	r.IdentityIndicatorMatchesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vertguard_identity_indicator_matches_total",
		Help: "Per-indicator identity match counter.",
	}, []string{"indicator_id", "category"})

	r.IdentityScanLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vertguard_identity_scan_latency_seconds",
		Help:    "Identity scan latency.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
	}, []string{"classification"})

	r.IdentityReplayHitsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "vertguard_identity_replay_hits_total",
		Help: "Replay-window threshold hits on identity scans.",
	})

	reg.MustRegister(
		r.HTTPRequestsTotal,
		r.HTTPRequestDuration,
		r.PromptScansTotal,
		r.PatternMatchesTotal,
		r.PromptScanLatency,
		r.PromptMLErrorsTotal,
		r.ThreatFeedIOCsTotal,
		r.ThreatFeedPushTotal,
		r.ThreatFeedStalenessSecs,
		r.CitadelCallsTotal,
		r.CitadelLatencySecs,
		r.WORMEmitTotal,
		r.CitadelQueueDepth,
		r.PhishingScansTotal,
		r.PhishingIndicatorMatchesTotal,
		r.PhishingScanLatency,
		r.AuditEventsTotal,
		r.RateLimitedTotal,
		r.JWTSecretUsedTotal,
		r.AdminSyncTotal,
		r.DenylistSize,
		r.DenylistHitsTotal,
		r.RateLimitOverridesActive,
		r.RateLimitOverrideHitTotal,
		r.MLCallsTotal,
		r.MLLatencySeconds,
		r.MLBreakerOpenTotal,
		r.IdentityScansTotal,
		r.IdentityIndicatorMatchesTotal,
		r.IdentityScanLatency,
		r.IdentityReplayHitsTotal,
	)

	r.Webhook = newWebhookMetrics(reg)

	return r
}

// Prometheus returns the underlying registry for handler use.
func (r *Registry) Prometheus() *prometheus.Registry {
	return r.prom
}
