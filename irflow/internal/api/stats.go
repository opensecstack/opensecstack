package api

import (
	"net/http"

	"go.uber.org/zap"
)

// handleGetStats returns aggregated dashboard statistics for the IRFlow UI.
func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.incidents.Stats(r.Context())
	if err != nil {
		s.logger.Error("stats: aggregation failed", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "stats unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}
