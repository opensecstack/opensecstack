// Package handlers — scaffold stubs for Phase 4.1 endpoints.
//
// STATUS: Every handler here returns HTTP 501 Not Implemented with a
// pointer to the module doc that describes the intended contract.
// As modules come online in Phase 4.1, these are replaced with real
// implementations that dispatch to the respective Service layer.
package handlers

import (
	"encoding/json"
	"net/http"
)

type todoResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	DocRef  string `json:"doc_ref"`
	Message string `json:"message,omitempty"`
}

func writeTODO(w http.ResponseWriter, code string, docRef string, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(todoResponse{
		Error:   "endpoint not yet implemented",
		Code:    code,
		DocRef:  docRef,
		Message: msg,
	})
}

// Module 3 — Prompt Injection

func PromptScanTODO(w http.ResponseWriter, r *http.Request) {
	writeTODO(w, "phase_4_1_wip", "docs/module-3-prompt-injection.md",
		"Module 3 scaffold in place; Rust pattern engine integration pending")
}

func PromptScanGetTODO(w http.ResponseWriter, r *http.Request) {
	writeTODO(w, "phase_4_1_wip", "docs/module-3-prompt-injection.md", "")
}

// Module 4 — AI Threat Feed

func ThreatFeedIOCsTODO(w http.ResponseWriter, r *http.Request) {
	writeTODO(w, "phase_4_1_wip", "docs/module-4-ai-threat-feed.md", "")
}

func ThreatFeedAtlasTODO(w http.ResponseWriter, r *http.Request) {
	writeTODO(w, "phase_4_1_wip", "docs/mitre-atlas-mapping.md", "")
}

func ThreatFeedAtlasCoverageTODO(w http.ResponseWriter, r *http.Request) {
	writeTODO(w, "phase_4_1_wip", "docs/mitre-atlas-mapping.md", "")
}

// Admin endpoints

func AdminPatternsReloadTODO(w http.ResponseWriter, r *http.Request) {
	writeTODO(w, "phase_4_1_wip", "docs/module-3-prompt-injection.md", "")
}

func AdminAtlasSyncTODO(w http.ResponseWriter, r *http.Request) {
	writeTODO(w, "phase_4_1_wip", "docs/mitre-atlas-mapping.md", "")
}
