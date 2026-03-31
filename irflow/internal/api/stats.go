package api

import (
	"net/http"
)

// handleGetStats returns aggregated dashboard statistics for the IRFlow UI.
// Currently returns zeroed counters; will query the incident service once
// aggregation queries are implemented.
func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total": 0,
		"by_severity": map[string]int{
			"P1": 0,
			"P2": 0,
			"P3": 0,
			"P4": 0,
		},
		"by_status": map[string]int{
			"open":          0,
			"investigating": 0,
			"contained":     0,
			"closed":        0,
		},
		"by_source": map[string]int{
			"apiguard":   0,
			"citadel":    0,
			"threatflow": 0,
			"manual":     0,
		},
	})
}
