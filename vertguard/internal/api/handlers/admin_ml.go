package handlers

import (
	"context"
	"net/http"

	"github.com/opensecstack/vertguard/internal/ml"
)

// MLInfoProvider is the slice of *ml.Client the admin handler needs.
// Interface (not concrete *ml.Client) lets tests inject a fake without
// dialling gRPC.
type MLInfoProvider interface {
	ModelInfo(ctx context.Context) (*ml.ModelInfo, error)
}

// AdminMLHandler exposes /api/v1/admin/ml/info.
type AdminMLHandler struct {
	Client MLInfoProvider
}

// NewAdminMLHandler is the wiring constructor used by main.go.
func NewAdminMLHandler(c MLInfoProvider) *AdminMLHandler {
	return &AdminMLHandler{Client: c}
}

// Info handles GET /api/v1/admin/ml/info. Returns 503 if the ML
// service is unreachable (ErrMLUnavailable surfaces as breaker-open).
func (h *AdminMLHandler) Info(w http.ResponseWriter, r *http.Request) {
	if h.Client == nil {
		writeJSONError(w, http.StatusNotImplemented, "ml_disabled",
			"ML enricher is not configured on this server")
		return
	}
	info, err := h.Client.ModelInfo(r.Context())
	if err != nil {
		// Soft-surface ML being down: 503 is the right code for
		// "we exist but our backend dependency is sad".
		writeJSONError(w, http.StatusServiceUnavailable, "ml_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}
