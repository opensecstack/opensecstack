package metrics

import (
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

// counterValue reads the current value of a single-labelled counter out of
// the registry by scraping and matching on the metric name.
func gatherMetric(t *testing.T, reg *Registry, name string) []*dto.Metric {
	t.Helper()
	families, err := reg.Prometheus().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f.GetMetric()
		}
	}
	return nil
}

func labelValue(m *dto.Metric, name string) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

func TestNew_RegistersAllCollectors(t *testing.T) {
	r := New()
	if r == nil {
		t.Fatal("New() returned nil")
	}
	if r.Prometheus() == nil {
		t.Fatal("Prometheus() returned nil registry")
	}
	if r.Webhook == nil {
		t.Fatal("Webhook metrics not wired by New()")
	}

	families, err := r.Prometheus().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	if len(families) == 0 {
		t.Fatal("Gather() returned no metric families; expected collectors to be registered")
	}

	// Un-vectored collectors (plain Counter/Gauge) always expose their
	// zero value once registered, so they are safe to spot-check without
	// having recorded anything first.
	want := map[string]bool{
		"vertguard_citadel_queue_depth":        false,
		"vertguard_identity_replay_hits_total": false,
		"vertguard_webhook_outbox_size":        false,
	}
	for _, f := range families {
		if _, ok := want[f.GetName()]; ok {
			want[f.GetName()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected metric family %q to be registered, was not found", name)
		}
	}

	// Vectored collectors (CounterVec/HistogramVec/GaugeVec) only appear
	// in Gather() once a label combination has been observed — confirm
	// that path too so the whole registration surface is exercised.
	a := NewPromptMetricsAdapter(r)
	a.ObservePromptScan("CLEAN", 0.01)
	families, err = r.Prometheus().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	found := false
	for _, f := range families {
		if f.GetName() == "vertguard_prompt_scans_total" {
			found = true
		}
	}
	if !found {
		t.Error("vertguard_prompt_scans_total not present after recording an observation")
	}
}

func TestNew_DoubleRegistrationPanics(t *testing.T) {
	// Registering the same collector name twice on one prometheus.Registry
	// panics via MustRegister; New() creates its own registry each call so
	// this documents/protects that isolation — two independent Registries
	// must not collide.
	r1 := New()
	r2 := New()
	if r1.Prometheus() == r2.Prometheus() {
		t.Fatal("two calls to New() shared the same underlying prometheus.Registry")
	}
}

func TestPromptMetricsAdapter_ObservePromptScan(t *testing.T) {
	r := New()
	a := NewPromptMetricsAdapter(r)

	a.ObservePromptScan("BLOCKED", 0.25)

	metrics := gatherMetric(t, r, "vertguard_prompt_scans_total")
	if len(metrics) != 1 {
		t.Fatalf("len(metrics) = %d, want 1", len(metrics))
	}
	if got := metrics[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("counter value = %v, want 1", got)
	}
	if got := labelValue(metrics[0], "classification"); got != "BLOCKED" {
		t.Errorf("classification label = %q, want BLOCKED", got)
	}
}

func TestPromptMetricsAdapter_IncPatternMatch(t *testing.T) {
	r := New()
	a := NewPromptMetricsAdapter(r)

	a.IncPatternMatch("PI-001", "injection")
	a.IncPatternMatch("PI-001", "injection")

	metrics := gatherMetric(t, r, "vertguard_pattern_matches_total")
	if len(metrics) != 1 {
		t.Fatalf("len(metrics) = %d, want 1", len(metrics))
	}
	if got := metrics[0].GetCounter().GetValue(); got != 2 {
		t.Errorf("counter value = %v, want 2 after two increments", got)
	}
}

func TestCitadelMetricsAdapter(t *testing.T) {
	r := New()
	a := NewCitadelMetricsAdapter(r)

	a.IncWORMEmit("prompt_scan", "ok")
	a.IncCitadelCall("marshal", "ok")
	a.ObserveCitadelLatency("marshal", 0.1)
	a.SetCitadelQueueDepth(7)

	if got := gatherMetric(t, r, "vertguard_worm_emit_total")[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("worm_emit_total = %v, want 1", got)
	}
	if got := gatherMetric(t, r, "vertguard_citadel_calls_total")[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("citadel_calls_total = %v, want 1", got)
	}
	queueMetrics := gatherMetric(t, r, "vertguard_citadel_queue_depth")
	if len(queueMetrics) != 1 {
		t.Fatalf("len(queueMetrics) = %d, want 1", len(queueMetrics))
	}
	if got := queueMetrics[0].GetGauge().GetValue(); got != 7 {
		t.Errorf("citadel_queue_depth = %v, want 7", got)
	}
}

func TestRateLimitMetricsAdapter(t *testing.T) {
	r := New()
	a := NewRateLimitMetricsAdapter(r)

	a.IncRateLimited("global")
	a.IncOverrideHit("sub", "limited")
	a.SetActiveOverrides(3)

	if got := gatherMetric(t, r, "vertguard_rate_limited_total")[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("rate_limited_total = %v, want 1", got)
	}
	overrideMetrics := gatherMetric(t, r, "vertguard_ratelimit_override_hits_total")
	if len(overrideMetrics) != 1 {
		t.Fatalf("len(overrideMetrics) = %d, want 1", len(overrideMetrics))
	}
	if got := labelValue(overrideMetrics[0], "decision"); got != "limited" {
		t.Errorf("decision label = %q, want limited", got)
	}
	activeMetrics := gatherMetric(t, r, "vertguard_ratelimit_overrides_active")
	if got := activeMetrics[0].GetGauge().GetValue(); got != 3 {
		t.Errorf("overrides_active = %v, want 3", got)
	}
}

func TestDenylistMetricsAdapter(t *testing.T) {
	r := New()
	a := NewDenylistMetricsAdapter(r)

	a.SetDenylistSize(42)
	a.IncDenylistHit("jti")

	sizeMetrics := gatherMetric(t, r, "vertguard_denylist_size")
	if got := sizeMetrics[0].GetGauge().GetValue(); got != 42 {
		t.Errorf("denylist_size = %v, want 42", got)
	}
	hitMetrics := gatherMetric(t, r, "vertguard_denylist_hits_total")
	if got := labelValue(hitMetrics[0], "kind"); got != "jti" {
		t.Errorf("kind label = %q, want jti", got)
	}
}

func TestMLMetricsAdapter(t *testing.T) {
	r := New()
	a := NewMLMetricsAdapter(r)

	a.IncMLCall("score_prompt", "ok")
	a.ObserveMLLatency("score_prompt", 0.05)
	a.IncBreakerOpen("score_prompt")

	if got := gatherMetric(t, r, "vertguard_ml_calls_total")[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("ml_calls_total = %v, want 1", got)
	}
	if got := gatherMetric(t, r, "vertguard_ml_breaker_open_total")[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("ml_breaker_open_total = %v, want 1", got)
	}
}

func TestIdentityMetricsAdapter(t *testing.T) {
	r := New()
	a := NewIdentityMetricsAdapter(r)

	a.ObserveIdentityScan("SUSPICIOUS", 0.02)
	a.IncIdentityIndicatorMatch("ID-001", "impersonation")
	a.IncIdentityReplayHit()

	if got := gatherMetric(t, r, "vertguard_identity_scans_total")[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("identity_scans_total = %v, want 1", got)
	}
	if got := gatherMetric(t, r, "vertguard_identity_replay_hits_total")[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("identity_replay_hits_total = %v, want 1", got)
	}
}

func TestAuthMetricsAdapter(t *testing.T) {
	r := New()
	a := NewAuthMetricsAdapter(r)
	a.IncSecretUsed("next")

	m := gatherMetric(t, r, "vertguard_jwt_secret_used_total")
	if got := labelValue(m[0], "slot"); got != "next" {
		t.Errorf("slot label = %q, want next", got)
	}
}

func TestAdminMetricsAdapter(t *testing.T) {
	r := New()
	a := NewAdminMetricsAdapter(r)
	a.IncAdminSync("atlas", "ok")

	m := gatherMetric(t, r, "vertguard_admin_sync_total")
	if got := labelValue(m[0], "kind"); got != "atlas" {
		t.Errorf("kind label = %q, want atlas", got)
	}
	if got := labelValue(m[0], "result"); got != "ok" {
		t.Errorf("result label = %q, want ok", got)
	}
}

func TestPhishingMetricsAdapter(t *testing.T) {
	r := New()
	a := NewPhishingMetricsAdapter(r)
	a.ObservePhishingScan("CLEAN", 0.01)
	a.IncPhishingIndicatorMatch("PH-001", "url")

	if got := gatherMetric(t, r, "vertguard_phishing_scans_total")[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("phishing_scans_total = %v, want 1", got)
	}
}

func TestAuditMetricsAdapter(t *testing.T) {
	r := New()
	a := NewAuditMetricsAdapter(r)
	a.IncAuditEvent("success")

	m := gatherMetric(t, r, "vertguard_audit_events_total")
	if got := labelValue(m[0], "outcome"); got != "success" {
		t.Errorf("outcome label = %q, want success", got)
	}
}

func TestThreatFlowMetricsAdapter(t *testing.T) {
	r := New()
	a := NewThreatFlowMetricsAdapter(r)
	a.IncThreatFeedPush("threatflow", "ok")

	m := gatherMetric(t, r, "vertguard_threatfeed_push_total")
	if len(m) != 1 {
		t.Fatalf("len(metrics) = %d, want 1", len(m))
	}
	if got := labelValue(m[0], "target"); got != "threatflow" {
		t.Errorf("target label = %q, want threatflow", got)
	}
}

// --- ioc.go ---

func TestNewIOCMetricsAdapter_RecordsOnRegistry(t *testing.T) {
	r := New()
	m := NewIOCMetricsAdapter(r)

	m.IncPull("community", "ok")
	m.IncFailure("community")
	m.SetActive(5)

	pulls := gatherMetric(t, r, "vertguard_ioc_pull_total")
	if len(pulls) != 1 {
		t.Fatalf("len(pulls) = %d, want 1", len(pulls))
	}
	if got := pulls[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("pull counter = %v, want 1", got)
	}

	failures := gatherMetric(t, r, "vertguard_ioc_pull_failures_total")
	if got := failures[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("failure counter = %v, want 1", got)
	}

	active := gatherMetric(t, r, "vertguard_ioc_active_total")
	if got := active[0].GetGauge().GetValue(); got != 5 {
		t.Errorf("active gauge = %v, want 5", got)
	}
}

func TestNewIOCMetricsAdapter_NilRegistrySafe(t *testing.T) {
	// Passing a nil *Registry must not panic — used when the puller runs
	// without a registry wired up.
	m := NewIOCMetricsAdapter(nil)
	m.IncPull("x", "ok")
	m.IncFailure("x")
	m.SetActive(1)
}

func TestNopIOCMetrics_NoPanics(t *testing.T) {
	var m NopIOCMetrics
	m.IncPull("x", "ok")
	m.IncFailure("x")
	m.SetActive(1)
}

// --- webhook.go ---

func TestWebhookMetrics_Recorders(t *testing.T) {
	r := New()

	r.IncWebhookDispatch("ok")
	r.ObserveWebhookLatency(0.2)
	r.SetWebhookOutboxSize(9)
	r.IncWebhookRotation()

	dispatch := gatherMetric(t, r, "vertguard_webhook_dispatch_total")
	if len(dispatch) != 1 {
		t.Fatalf("len(dispatch) = %d, want 1", len(dispatch))
	}
	if got := dispatch[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("dispatch counter = %v, want 1", got)
	}

	outbox := gatherMetric(t, r, "vertguard_webhook_outbox_size")
	if got := outbox[0].GetGauge().GetValue(); got != 9 {
		t.Errorf("outbox size = %v, want 9", got)
	}

	rotation := gatherMetric(t, r, "vertguard_webhook_rotation_total")
	if got := rotation[0].GetCounter().GetValue(); got != 1 {
		t.Errorf("rotation counter = %v, want 1", got)
	}
}

func TestWebhookMetrics_NilRegistrySafe(t *testing.T) {
	// A zero-value Registry (nil Webhook field) must not panic — guards
	// callers that fail to wire metrics before use.
	var r *Registry
	r.IncWebhookDispatch("ok")
	r.ObserveWebhookLatency(0.1)
	r.SetWebhookOutboxSize(1)
	r.IncWebhookRotation()

	rNoWebhook := &Registry{}
	rNoWebhook.IncWebhookDispatch("ok")
	rNoWebhook.ObserveWebhookLatency(0.1)
	rNoWebhook.SetWebhookOutboxSize(1)
	rNoWebhook.IncWebhookRotation()
}

func TestMetricNamesHaveVertguardPrefix(t *testing.T) {
	r := New()
	families, err := r.Prometheus().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, f := range families {
		if !strings.HasPrefix(f.GetName(), "vertguard_") {
			t.Errorf("metric %q missing vertguard_ prefix", f.GetName())
		}
	}
}
