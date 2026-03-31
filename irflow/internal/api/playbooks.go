package api

import (
	"net/http"
)

func (s *Server) handleListPlaybooks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "playbooks not yet implemented",
	})
}

func (s *Server) handleCreatePlaybook(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "playbooks not yet implemented",
	})
}

func (s *Server) handleGetPlaybook(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "playbooks not yet implemented",
	})
}

func (s *Server) handlePatchPlaybook(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "playbooks not yet implemented",
	})
}

func (s *Server) handleDeletePlaybook(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "playbooks not yet implemented",
	})
}

func (s *Server) handleExecutePlaybook(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "playbooks not yet implemented",
	})
}
