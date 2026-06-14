// Admin-facing content endpoint(s).
//
// /api/v1/admin/content/reload — POST. Re-scans the configured content
// directory and re-publishes every track whose content_hash changed.
//
// TODO(v1.0.0): real admin role check. Today the route is gated only
// by the rbacStub middleware in server.go (which currently passes
// through). The first proper RBAC pass will enforce the "admin" role
// claim before reaching this handler.
package handlers

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/cyberpath/internal/content"
)

// ContentAdminHandler exposes admin-only content lifecycle endpoints.
type ContentAdminHandler struct {
	Service *content.Service
	Logger  *zerolog.Logger
}

// NewContentAdminHandler constructs a ContentAdminHandler.
func NewContentAdminHandler(svc *content.Service, logger *zerolog.Logger) *ContentAdminHandler {
	return &ContentAdminHandler{Service: svc, Logger: logger}
}

// Reload triggers Service.Reload and returns the published / unchanged /
// failed counts. byUser is uuid.Nil today — once auth context carries
// a user id we'll thread it through here.
func (h *ContentAdminHandler) Reload() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.Service == nil {
			writeError(w, http.StatusServiceUnavailable, "content_unavailable",
				"content service not configured")
			return
		}
		report, err := h.Service.Reload(r.Context(), uuid.Nil)
		if err != nil {
			if h.Logger != nil {
				h.Logger.Error().Err(err).Msg("content reload failed")
			}
			writeError(w, http.StatusInternalServerError, "reload_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"published_count": len(report.Published),
			"unchanged_count": len(report.Unchanged),
			"failed_count":    len(report.Failed),
			"published":       report.Published,
			"unchanged":       report.Unchanged,
			"failed":          report.Failed,
		})
	}
}
