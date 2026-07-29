package handlers

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/db"
)

// Audit handles audit log endpoints.
type Audit struct {
	logger zerolog.Logger
	db     *db.DB
}

// NewAudit creates a new Audit handler.
func NewAudit(logger zerolog.Logger, database *db.DB) *Audit {
	return &Audit{
		logger: logger.With().Str("handler", "audit").Logger(),
		db:     database,
	}
}

// List handles GET /api/v1/audit.
// Query params: actor_id, action, resource_id, resource_type, page, per_page
func (a *Audit) List(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r, 1, 50, 100)

	q := r.URL.Query()
	filters := db.AuditLogFilters{}
	if v := q.Get("actor_id"); v != "" {
		filters.ActorID = &v
	}
	if v := q.Get("action"); v != "" {
		switch db.AuditAction(v) {
		case db.AuditActionScanCreated,
			db.AuditActionScanStarted,
			db.AuditActionScanCompleted,
			db.AuditActionScanFailed,
			db.AuditActionScanDeleted,
			db.AuditActionFindingTriaged,
			db.AuditActionFindingStatusChanged,
			db.AuditActionSpecUploaded,
			db.AuditActionSpecParsed,
			db.AuditActionReportGenerated,
			db.AuditActionReportExported,
			db.AuditActionAPIKeyCreated,
			db.AuditActionAPIKeyRevoked,
			db.AuditActionScanApprovalRequested,
			db.AuditActionScanApprovalApproved,
			db.AuditActionScanApprovalRejected:
			action := db.AuditAction(v)
			filters.Action = &action
		default:
			writeError(w, http.StatusBadRequest, "invalid action filter")
			return
		}
	}
	if v := q.Get("resource_type"); v != "" {
		filters.ResourceType = &v
	}
	// resource_id must be a valid UUID; reject invalid values with 400.
	if v := q.Get("resource_id"); v != "" {
		parsed, err := uuid.Parse(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "resource_id must be a valid UUID")
			return
		}
		filters.ResourceID = &parsed
	}

	entries, total, err := a.db.ListAuditLog(r.Context(), filters, page, perPage)
	if err != nil {
		a.logger.Error().Err(err).Msg("listing audit log")
		writeError(w, http.StatusInternalServerError, "failed to list audit log")
		return
	}

	// A-M6: return the same wrapped response shape as other list endpoints.
	// Keep X-Total-Count for backwards compatibility.
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":     entries,
		"total":    total,
		"page":     page,
		"per_page": perPage,
	})
}
