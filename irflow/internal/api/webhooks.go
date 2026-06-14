package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/incident"
	"github.com/opensecstack/opensecstack/irflow/internal/webhook"
)

// handleAPIGuardWebhook accepts scan findings from APIGuard. A CRITICAL-severity
// finding auto-creates an incident; lower severities are acknowledged but do
// not trigger incident creation (APIGuard already manages its own findings).
func (s *Server) handleAPIGuardWebhook(w http.ResponseWriter, r *http.Request) {
	body, ok := s.verifyWebhook(w, r, s.webhooks.APIGuard, "apiguard")
	if !ok {
		return
	}

	var evt webhook.APIGuardEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		writeError(w, http.StatusBadRequest, "invalid APIGuard payload")
		return
	}

	if s.incidents == nil {
		writeError(w, http.StatusServiceUnavailable, "incident service unavailable")
		return
	}

	severity := mapAPIGuardSeverity(evt.Finding.Severity)
	// Acknowledge below-threshold findings without creating an incident.
	// A future correlation engine may attach them to an existing incident.
	if severity == "" {
		writeJSON(w, http.StatusAccepted, map[string]string{
			"status":   "acknowledged",
			"event_id": evt.EventID,
			"action":   "below threshold",
		})
		return
	}

	title := evt.Finding.Title
	if title == "" {
		title = "APIGuard finding"
	}
	req := &incident.CreateIncidentRequest{
		Title:       title,
		Description: evt.Finding.Description,
		Severity:    severity,
		Source:      incident.SourceAPIGuard,
		SourceRef:   evt.ScanID,
	}
	inc, err := s.incidents.Create(r.Context(), req)
	if err != nil {
		s.logger.Error("apiguard webhook: create incident failed",
			zap.String("event_id", evt.EventID), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	s.logger.Info("apiguard webhook: incident created",
		zap.String("event_id", evt.EventID),
		zap.String("incident_id", inc.ID),
		zap.String("severity", string(severity)),
	)
	writeJSON(w, http.StatusCreated, inc)
}

// handleCITADELWebhook accepts governance events from CITADEL. A HARD_STOP
// always produces a P1 incident for immediate response. Other event types
// (marshal_denied, worm_tamper, etc.) are acknowledged and logged but do not
// auto-create incidents.
func (s *Server) handleCITADELWebhook(w http.ResponseWriter, r *http.Request) {
	body, ok := s.verifyWebhook(w, r, s.webhooks.CITADEL, "citadel")
	if !ok {
		return
	}

	var evt webhook.CITADELEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		writeError(w, http.StatusBadRequest, "invalid CITADEL payload")
		return
	}

	if s.incidents == nil {
		writeError(w, http.StatusServiceUnavailable, "incident service unavailable")
		return
	}

	if strings.ToLower(evt.EventType) != "hard_stop" {
		s.logger.Info("citadel webhook: non-hard-stop event acknowledged",
			zap.String("event_id", evt.EventID),
			zap.String("event_type", evt.EventType),
		)
		writeJSON(w, http.StatusAccepted, map[string]string{
			"status":     "acknowledged",
			"event_id":   evt.EventID,
			"event_type": evt.EventType,
		})
		return
	}

	title := "CITADEL HARD STOP: " + evt.Trigger
	if evt.Trigger == "" {
		title = "CITADEL HARD STOP"
	}
	desc := evt.Description
	if desc == "" {
		desc = "CITADEL governance engine issued a HARD STOP. Immediate response required."
	}
	req := &incident.CreateIncidentRequest{
		Title:       title,
		Description: desc,
		Severity:    incident.SeverityP1,
		Source:      incident.SourceCitadel,
		SourceRef:   evt.ExecutionID,
		ProjectID:   evt.ProjectID,
	}
	inc, err := s.incidents.Create(r.Context(), req)
	if err != nil {
		s.logger.Error("citadel webhook: create incident failed",
			zap.String("event_id", evt.EventID), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	s.logger.Warn("citadel webhook: P1 incident created from HARD STOP",
		zap.String("event_id", evt.EventID),
		zap.String("incident_id", inc.ID),
		zap.String("trigger", evt.Trigger),
	)
	writeJSON(w, http.StatusCreated, inc)
}

// handleThreatFlowWebhook accepts IOC bundles from ThreatFlow. When the event
// names an incident_id, the IOCs are attached directly. Without an incident
// target the event is acknowledged and queued for later correlation (the
// correlation engine is a planned post-v1.0 feature).
func (s *Server) handleThreatFlowWebhook(w http.ResponseWriter, r *http.Request) {
	body, ok := s.verifyWebhook(w, r, s.webhooks.ThreatFlow, "threatflow")
	if !ok {
		return
	}

	var evt webhook.ThreatFlowEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		writeError(w, http.StatusBadRequest, "invalid ThreatFlow payload")
		return
	}

	if s.incidents == nil {
		writeError(w, http.StatusServiceUnavailable, "incident service unavailable")
		return
	}

	if evt.IncidentID == "" {
		s.logger.Info("threatflow webhook: bundle accepted without incident target",
			zap.String("event_id", evt.EventID),
			zap.Int("ioc_count", len(evt.IOCs)),
		)
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"status":    "queued",
			"event_id":  evt.EventID,
			"ioc_count": len(evt.IOCs),
			"note":      "no incident_id — queued for correlation",
		})
		return
	}

	attached := 0
	for _, src := range evt.IOCs {
		ioc := &incident.IOCEnrichment{
			IOCType:    src.Type,
			IOCValue:   src.Value,
			Confidence: src.Confidence,
			Source:     src.Source,
			STIXBundle: src.STIXBundle,
		}
		if _, err := s.incidents.AddIOC(r.Context(), evt.IncidentID, ioc); err != nil {
			s.logger.Error("threatflow webhook: add IOC failed",
				zap.String("event_id", evt.EventID),
				zap.String("incident_id", evt.IncidentID),
				zap.String("ioc", src.Value),
				zap.Error(err),
			)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		attached++
	}
	s.logger.Info("threatflow webhook: incident enriched",
		zap.String("event_id", evt.EventID),
		zap.String("incident_id", evt.IncidentID),
		zap.Int("attached", attached),
	)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "enriched",
		"event_id":    evt.EventID,
		"incident_id": evt.IncidentID,
		"attached":    attached,
	})
}

// verifyWebhook reads the request body under a size limit and verifies the
// HMAC signature for the given source. On failure it writes the appropriate
// response and returns ok=false; callers must early-return.
func (s *Server) verifyWebhook(w http.ResponseWriter, r *http.Request, secret, source string) ([]byte, bool) {
	if secret == "" {
		s.logger.Error("webhook: secret not configured", zap.String("source", source))
		s.metrics.WebhookReceived(source, "error")
		writeError(w, http.StatusServiceUnavailable, "webhook not configured")
		return nil, false
	}

	limit := s.webhooks.MaxBodySize
	if limit <= 0 {
		limit = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		s.metrics.WebhookReceived(source, "rejected_payload")
		writeError(w, http.StatusBadRequest, "failed to read body")
		return nil, false
	}
	if int64(len(body)) > limit {
		s.metrics.WebhookReceived(source, "rejected_payload")
		writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
		return nil, false
	}

	verifier, err := webhook.NewVerifier(secret, s.webhooks.ClockSkew)
	if err != nil {
		s.logger.Error("webhook: verifier init failed",
			zap.String("source", source), zap.Error(err))
		s.metrics.WebhookReceived(source, "error")
		writeError(w, http.StatusServiceUnavailable, "webhook not configured")
		return nil, false
	}

	sig := r.Header.Get(webhook.HeaderSignature)
	ts := r.Header.Get(webhook.HeaderTimestamp)
	if err := verifier.Verify(body, sig, ts); err != nil {
		s.logger.Warn("webhook: signature verification failed",
			zap.String("source", source),
			zap.String("remote_addr", r.RemoteAddr),
			zap.Error(err),
		)
		s.metrics.WebhookReceived(source, "rejected_signature")
		writeError(w, webhookHTTPStatus(err), err.Error())
		return nil, false
	}
	s.metrics.WebhookReceived(source, "accepted")
	return body, true
}

func webhookHTTPStatus(err error) int {
	switch {
	case errors.Is(err, webhook.ErrMissingSignature),
		errors.Is(err, webhook.ErrMissingTimestamp),
		errors.Is(err, webhook.ErrInvalidTimestamp):
		return http.StatusBadRequest
	case errors.Is(err, webhook.ErrStaleTimestamp),
		errors.Is(err, webhook.ErrInvalidSignature):
		return http.StatusUnauthorized
	default:
		return http.StatusBadRequest
	}
}

// mapAPIGuardSeverity converts APIGuard's finding severity string into an
// IRFlow incident severity. Returns "" for below-threshold severities
// (medium/low/informational) which do not auto-create incidents.
func mapAPIGuardSeverity(s string) incident.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return incident.SeverityP1
	case "high":
		return incident.SeverityP2
	default:
		return ""
	}
}
