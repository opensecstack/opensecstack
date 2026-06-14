package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/incident"
	"github.com/opensecstack/opencsirt/internal/metrics"
)

var irflowSeverityCoercionTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "opencsirt_irflow_severity_coercion_total",
	Help: "IRFlow severity values coerced to a supported value, labelled by original and coerced.",
}, []string{"original", "coerced"})

func init() {
	metrics.Registry.MustRegister(irflowSeverityCoercionTotal)
}

// IRFlowWebhook receives `incident.escalated` webhooks from IRFlow.
// Verifies HMAC-SHA256 signature against IRFlow webhook spec, then
// converts the IRFlow incident into an OpenCSIRT incident.
type IRFlowWebhook struct {
	secret         []byte
	svc            *incident.Service
	logger         zerolog.Logger
	strictSeverity bool
}

// IRFlowConfig carries runtime configuration for IRFlowWebhook.
type IRFlowConfig struct {
	// Secret is the shared HMAC secret for webhook signature verification.
	Secret string
	// StrictSeverity causes the handler to reject (HTTP 400) any incoming
	// severity that would be coerced — most importantly "critical" → "medium".
	// When false the coercion is logged and counted but accepted.
	StrictSeverity bool
}

func NewIRFlowWebhook(cfg IRFlowConfig, svc *incident.Service, logger zerolog.Logger) *IRFlowWebhook {
	return &IRFlowWebhook{
		secret:         []byte(cfg.Secret),
		svc:            svc,
		logger:         logger,
		strictSeverity: cfg.StrictSeverity,
	}
}

type irflowIncident struct {
	ID       string         `json:"id"`
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Summary  string         `json:"summary"`
	OpenedAt string         `json:"opened_at"`
	Tenant   string         `json:"tenant_id"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

func (h *IRFlowWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	if err := VerifyHMAC(h.secret, r.Header.Get("X-Timestamp"), r.Header.Get("X-Signature"), body); err != nil {
		h.logger.Warn().Err(err).Msg("irflow: hmac verify failed")
		http.Error(w, "signature invalid", http.StatusUnauthorized)
		return
	}
	var in irflowIncident
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	severity := in.Severity
	switch severity {
	case "low", "medium", "high", "critical":
		// recognised — no coercion needed
	default:
		coerced := "medium"
		h.logger.Warn().
			Str("original_severity", severity).
			Str("coerced_severity", coerced).
			Msg("irflow: unrecognised severity coerced")
		labelVal := severity
		if len(labelVal) > 32 {
			labelVal = "other"
		}
		irflowSeverityCoercionTotal.WithLabelValues(labelVal, coerced).Inc()

		// Reject rather than silently downgrade when StrictSeverity is enabled.
		if h.strictSeverity {
			http.Error(w, "unrecognised severity: "+severity, http.StatusBadRequest)
			return
		}
		severity = coerced
	}

	// IRFlow incident metadata becomes opencsirt metadata.
	meta := in.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	meta["irflow_id"] = in.ID
	meta["irflow_tenant"] = in.Tenant

	inc, err := h.svc.Create(r.Context(), incident.CreateInput{
		Source:      "irflow",
		Severity:    severity,
		Title:       in.Title,
		Description: in.Summary,
		Metadata:    meta,
	}, uuid.Nil, "irflow_webhook")
	if err != nil {
		if errors.Is(err, incident.ErrInvalidSource) ||
			errors.Is(err, incident.ErrInvalidSeverity) ||
			errors.Is(err, incident.ErrEmptyTitle) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			h.logger.Error().Err(err).Msg("irflow: incident create failed")
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"incident_id": inc.ID})
}

// Compile-time check that we satisfy http.Handler.
var _ http.Handler = (*IRFlowWebhook)(nil)

// Background worker pattern (no-op for IRFlow; webhooks are pull from
// our side). Provided for symmetry with VertGuard.
func (h *IRFlowWebhook) Run(_ context.Context) {}
