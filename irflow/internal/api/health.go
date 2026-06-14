package api

import (
	"net/http"

	"github.com/opensecstack/opensecstack/irflow/internal/version"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleHealthDetail(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"status":  "ok",
		"version": version.Version,
		"commit":  version.GitCommit,
		"built":   version.BuildDate,
		"db":      "unknown",
	}

	if s.pinger != nil {
		if err := s.pinger.Ping(r.Context()); err != nil {
			resp["status"] = "degraded"
			resp["db"] = "unreachable"
			writeJSON(w, http.StatusServiceUnavailable, resp)
			return
		}
		resp["db"] = "ok"
	}

	writeJSON(w, http.StatusOK, resp)
}
