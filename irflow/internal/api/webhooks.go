package api

import (
	"net/http"

	"go.uber.org/zap"
)

// handleAPIGuardWebhook receives scan-result events from APIGuard.
// When implemented it will: validate the request signature, parse the scan
// result payload, and auto-create a P1 incident when severity is CRITICAL.
func (s *Server) handleAPIGuardWebhook(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("received APIGuard webhook",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("remote_addr", r.RemoteAddr),
	)

	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error":   "apiguard webhook not yet implemented",
		"planned": "will validate signature, parse scan-result event, and auto-create incident on CRITICAL severity",
	})
}

// handleCITADELWebhook receives compliance events from CITADEL.
// When implemented it will: validate the request signature, parse HARD_STOP
// events, and auto-create a P1 incident for immediate response.
func (s *Server) handleCITADELWebhook(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("received CITADEL webhook",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("remote_addr", r.RemoteAddr),
	)

	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error":   "citadel webhook not yet implemented",
		"planned": "will validate signature, parse HARD_STOP event, and auto-create P1 incident",
	})
}

// handleThreatFlowWebhook receives IOC bundles from ThreatFlow.
// When implemented it will: validate the request signature, parse the IOC
// bundle, and enrich any matching open incidents with the new indicators.
func (s *Server) handleThreatFlowWebhook(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("received ThreatFlow webhook",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("remote_addr", r.RemoteAddr),
	)

	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error":   "threatflow webhook not yet implemented",
		"planned": "will validate signature, parse IOC bundle, and enrich matching incidents",
	})
}
