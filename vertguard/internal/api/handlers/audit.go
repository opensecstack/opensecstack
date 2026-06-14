package handlers

import (
	"context"
	"net/http"

	"github.com/opensecstack/vertguard/internal/audit"
)

// AuditLister is the read surface AuditHandler needs from the store —
// stays mockable.
type AuditLister interface {
	ListAuditEvents(ctx context.Context, limit int, sinceID string) ([]audit.Event, error)
}

// AuditHandler serves admin-only audit queries.
type AuditHandler struct {
	Store AuditLister
}

// NewAuditHandler is a convenience constructor.
func NewAuditHandler(s AuditLister) *AuditHandler { return &AuditHandler{Store: s} }

// List handles GET /api/v1/admin/audit?limit=&since=.
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "audit store not configured")
		return
	}
	limit := parseIntQuery(r, "limit", 100)
	since := r.URL.Query().Get("since")

	events, err := h.Store.ListAuditEvents(r.Context(), limit, since)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events)})
}

func parseIntQuery(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return def
		}
	}
	if n == 0 {
		return def
	}
	return n
}
