package metrics

import "github.com/prometheus/client_golang/prometheus"

// WebhookMetrics carries the VG-015 outbound dispatcher collectors.
// Lives on its own struct to keep the surface change to Registry
// additive (just an embedded *WebhookMetrics field initialised in New).
type WebhookMetrics struct {
	DispatchTotal   *prometheus.CounterVec
	DispatchLatency prometheus.Histogram
	OutboxSize      prometheus.Gauge
	RotationTotal   prometheus.Counter
}

// newWebhookMetrics constructs and registers the collectors.
func newWebhookMetrics(reg *prometheus.Registry) *WebhookMetrics {
	m := &WebhookMetrics{
		DispatchTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vertguard_webhook_dispatch_total",
			Help: "Outbound webhook dispatch outcomes (ok|fail).",
		}, []string{"result"}),
		DispatchLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "vertguard_webhook_dispatch_latency_seconds",
			Help:    "Outbound webhook dispatch latency.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10},
		}),
		OutboxSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vertguard_webhook_outbox_size",
			Help: "Pending outbound webhook outbox rows.",
		}),
		RotationTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vertguard_webhook_rotation_total",
			Help: "HMAC rotations triggered by the admin API.",
		}),
	}
	reg.MustRegister(m.DispatchTotal, m.DispatchLatency, m.OutboxSize, m.RotationTotal)
	return m
}

// IncWebhookDispatch records one dispatch outcome.
func (r *Registry) IncWebhookDispatch(result string) {
	if r == nil || r.Webhook == nil {
		return
	}
	r.Webhook.DispatchTotal.WithLabelValues(result).Inc()
}

// ObserveWebhookLatency records one dispatch latency sample.
func (r *Registry) ObserveWebhookLatency(seconds float64) {
	if r == nil || r.Webhook == nil {
		return
	}
	r.Webhook.DispatchLatency.Observe(seconds)
}

// SetWebhookOutboxSize sets the pending-outbox gauge.
func (r *Registry) SetWebhookOutboxSize(n int) {
	if r == nil || r.Webhook == nil {
		return
	}
	r.Webhook.OutboxSize.Set(float64(n))
}

// IncWebhookRotation increments the rotation counter.
func (r *Registry) IncWebhookRotation() {
	if r == nil || r.Webhook == nil {
		return
	}
	r.Webhook.RotationTotal.Inc()
}
