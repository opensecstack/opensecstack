package metrics

// PromptMetricsAdapter implements handlers.PromptMetrics against the
// full Registry. Keeps handler coupling minimal (handler doesn't
// import the whole metrics package).
type PromptMetricsAdapter struct {
	reg *Registry
}

// NewPromptMetricsAdapter wires the Registry for Module 3 handlers.
func NewPromptMetricsAdapter(r *Registry) *PromptMetricsAdapter {
	return &PromptMetricsAdapter{reg: r}
}

// ObservePromptScan records one prompt scan outcome.
func (a *PromptMetricsAdapter) ObservePromptScan(classification string, durationSec float64) {
	a.reg.PromptScansTotal.WithLabelValues(classification).Inc()
	a.reg.PromptScanLatency.WithLabelValues(classification).Observe(durationSec)
}

// IncPatternMatch records one pattern hit.
func (a *PromptMetricsAdapter) IncPatternMatch(patternID, category string) {
	a.reg.PatternMatchesTotal.WithLabelValues(patternID, category).Inc()
}

// IncPromptMLError increments the prompt-side ML error counter. Wiring
// code (cmd/server/main.go) constructs a prompt.MLErrorReporter that
// calls this and warn-logs the first occurrence per (backend, class).
func (a *PromptMetricsAdapter) IncPromptMLError(backend, errClass string) {
	a.reg.PromptMLErrorsTotal.WithLabelValues(backend, errClass).Inc()
}

// PhishingMetricsAdapter implements handlers.PhishingMetrics.
type PhishingMetricsAdapter struct {
	reg *Registry
}

// NewPhishingMetricsAdapter wires the Registry for Module 5 handlers.
func NewPhishingMetricsAdapter(r *Registry) *PhishingMetricsAdapter {
	return &PhishingMetricsAdapter{reg: r}
}

// ObservePhishingScan records one phishing scan outcome.
func (a *PhishingMetricsAdapter) ObservePhishingScan(classification string, durationSec float64) {
	a.reg.PhishingScansTotal.WithLabelValues(classification).Inc()
	a.reg.PhishingScanLatency.WithLabelValues(classification).Observe(durationSec)
}

// IncPhishingIndicatorMatch records one indicator hit.
func (a *PhishingMetricsAdapter) IncPhishingIndicatorMatch(indicatorID, category string) {
	a.reg.PhishingIndicatorMatchesTotal.WithLabelValues(indicatorID, category).Inc()
}

// CitadelMetricsAdapter implements citadel.Metrics against Registry.
type CitadelMetricsAdapter struct {
	reg *Registry
}

// NewCitadelMetricsAdapter wires Registry for the CITADEL client.
func NewCitadelMetricsAdapter(r *Registry) *CitadelMetricsAdapter {
	return &CitadelMetricsAdapter{reg: r}
}

func (a *CitadelMetricsAdapter) IncWORMEmit(eventType, result string) {
	a.reg.WORMEmitTotal.WithLabelValues(eventType, result).Inc()
}

func (a *CitadelMetricsAdapter) IncCitadelCall(target, result string) {
	a.reg.CitadelCallsTotal.WithLabelValues(target, result).Inc()
}

func (a *CitadelMetricsAdapter) ObserveCitadelLatency(target string, durationSec float64) {
	a.reg.CitadelLatencySecs.WithLabelValues(target).Observe(durationSec)
}

func (a *CitadelMetricsAdapter) SetCitadelQueueDepth(n int) {
	a.reg.CitadelQueueDepth.Set(float64(n))
}

// ThreatFlowMetricsAdapter implements webhook.Metrics against Registry.
type ThreatFlowMetricsAdapter struct {
	reg *Registry
}

// NewThreatFlowMetricsAdapter wires Registry for the webhook publisher.
func NewThreatFlowMetricsAdapter(r *Registry) *ThreatFlowMetricsAdapter {
	return &ThreatFlowMetricsAdapter{reg: r}
}

func (a *ThreatFlowMetricsAdapter) IncThreatFeedPush(target, result string) {
	a.reg.ThreatFeedPushTotal.WithLabelValues(target, result).Inc()
}

// AuditMetricsAdapter implements audit.MetricsHook against Registry.
type AuditMetricsAdapter struct {
	reg *Registry
}

// NewAuditMetricsAdapter wires Registry for the audit middleware.
func NewAuditMetricsAdapter(r *Registry) *AuditMetricsAdapter {
	return &AuditMetricsAdapter{reg: r}
}

func (a *AuditMetricsAdapter) IncAuditEvent(outcome string) {
	a.reg.AuditEventsTotal.WithLabelValues(outcome).Inc()
}

// RateLimitMetricsAdapter implements ratelimit.Metrics against Registry.
type RateLimitMetricsAdapter struct {
	reg *Registry
}

// NewRateLimitMetricsAdapter wires Registry for the rate-limit middleware.
func NewRateLimitMetricsAdapter(r *Registry) *RateLimitMetricsAdapter {
	return &RateLimitMetricsAdapter{reg: r}
}

func (a *RateLimitMetricsAdapter) IncRateLimited(scope string) {
	a.reg.RateLimitedTotal.WithLabelValues(scope).Inc()
}

// IncOverrideHit records one request decision made against an
// override-derived bucket. kind is the override key prefix
// ("sub" or "ip"); decision is "allowed" or "limited".
func (a *RateLimitMetricsAdapter) IncOverrideHit(kind, decision string) {
	a.reg.RateLimitOverrideHitTotal.WithLabelValues(kind, decision).Inc()
}

// SetActiveOverrides reflects the override snapshot size after refresh.
func (a *RateLimitMetricsAdapter) SetActiveOverrides(n int) {
	a.reg.RateLimitOverridesActive.Set(float64(n))
}

// AuthMetricsAdapter implements auth.Metrics against Registry.
type AuthMetricsAdapter struct {
	reg *Registry
}

// NewAuthMetricsAdapter wires Registry for the JWT verifier.
func NewAuthMetricsAdapter(r *Registry) *AuthMetricsAdapter {
	return &AuthMetricsAdapter{reg: r}
}

// IncSecretUsed records that the verifier matched a token against the
// given slot ("primary", "next", or "previous").
func (a *AuthMetricsAdapter) IncSecretUsed(slot string) {
	a.reg.JWTSecretUsedTotal.WithLabelValues(slot).Inc()
}

// AdminMetricsAdapter implements handlers.AdminMetrics against Registry.
type AdminMetricsAdapter struct {
	reg *Registry
}

// NewAdminMetricsAdapter wires Registry for the admin endpoints.
func NewAdminMetricsAdapter(r *Registry) *AdminMetricsAdapter {
	return &AdminMetricsAdapter{reg: r}
}

// IncAdminSync records one operator-triggered sync/reload outcome.
// kind ∈ {"atlas","patterns"}; result ∈ {"ok","fail"}.
func (a *AdminMetricsAdapter) IncAdminSync(kind, result string) {
	a.reg.AdminSyncTotal.WithLabelValues(kind, result).Inc()
}

// DenylistMetricsAdapter implements denylist.MetricsHook against Registry.
type DenylistMetricsAdapter struct {
	reg *Registry
}

// NewDenylistMetricsAdapter wires Registry for the JWT denylist cache.
func NewDenylistMetricsAdapter(r *Registry) *DenylistMetricsAdapter {
	return &DenylistMetricsAdapter{reg: r}
}

// SetDenylistSize updates the snapshot size gauge.
func (a *DenylistMetricsAdapter) SetDenylistSize(n int) {
	a.reg.DenylistSize.Set(float64(n))
}

// IncDenylistHit records one revocation match.
func (a *DenylistMetricsAdapter) IncDenylistHit(kind string) {
	a.reg.DenylistHitsTotal.WithLabelValues(kind).Inc()
}

// MLMetricsAdapter implements ml.Metrics against Registry.
type MLMetricsAdapter struct {
	reg *Registry
}

// NewMLMetricsAdapter wires Registry for the ML enricher.
func NewMLMetricsAdapter(r *Registry) *MLMetricsAdapter {
	return &MLMetricsAdapter{reg: r}
}

// IncMLCall records one ML RPC outcome. result ∈ ok|fail|breaker_open|timeout.
func (a *MLMetricsAdapter) IncMLCall(rpc, result string) {
	a.reg.MLCallsTotal.WithLabelValues(rpc, result).Inc()
}

// ObserveMLLatency records one ML RPC latency observation in seconds.
func (a *MLMetricsAdapter) ObserveMLLatency(rpc string, sec float64) {
	a.reg.MLLatencySeconds.WithLabelValues(rpc).Observe(sec)
}

// IncBreakerOpen records that the breaker short-circuited an RPC.
func (a *MLMetricsAdapter) IncBreakerOpen(rpc string) {
	a.reg.MLBreakerOpenTotal.WithLabelValues(rpc).Inc()
}

// IdentityMetricsAdapter implements handlers.IdentityMetrics.
type IdentityMetricsAdapter struct {
	reg *Registry
}

// NewIdentityMetricsAdapter wires the Registry for Module 6 handlers.
func NewIdentityMetricsAdapter(r *Registry) *IdentityMetricsAdapter {
	return &IdentityMetricsAdapter{reg: r}
}

func (a *IdentityMetricsAdapter) ObserveIdentityScan(classification string, durationSec float64) {
	a.reg.IdentityScansTotal.WithLabelValues(classification).Inc()
	a.reg.IdentityScanLatency.WithLabelValues(classification).Observe(durationSec)
}

func (a *IdentityMetricsAdapter) IncIdentityIndicatorMatch(indicatorID, category string) {
	a.reg.IdentityIndicatorMatchesTotal.WithLabelValues(indicatorID, category).Inc()
}

func (a *IdentityMetricsAdapter) IncIdentityReplayHit() {
	a.reg.IdentityReplayHitsTotal.Inc()
}
