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
	q := r.URL.Query()

	page := 1
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid page parameter",
				"code":  "INVALID_INPUT",
			})
			return
		}
		if n > 0 {
			page = n
		}
	}

	perPage := 50
	if v := q.Get("per_page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid per_page parameter",
				"code":  "INVALID_INPUT",
			})
			return
		}
		if n > 0 {
			perPage = n
		}
	}
	if perPage > 100 {
		perPage = 100
	}

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
			db.AuditActionAPIKeyRevoked:
			action := db.AuditAction(v)
			filters.Action = &action
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid action filter",
				"code":  "INVALID_INPUT",
			})
			return
		}
	}
	if v := q.Get("resource_type"); v != "" {
		filters.ResourceType = &v
	}
	// resource_id is a UUID — skip if parse fails.
	if v := q.Get("resource_id"); v != "" {
		parsed, err := uuid.Parse(v)
		if err == nil {
			filters.ResourceID = &parsed
		}
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
