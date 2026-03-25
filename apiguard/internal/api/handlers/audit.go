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

	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(q.Get("per_page"))
	if perPage < 1 {
		perPage = 50
	}

	filters := db.AuditLogFilters{}
	if v := q.Get("actor_id"); v != "" {
		filters.ActorID = &v
	}
	if v := q.Get("action"); v != "" {
		action := db.AuditAction(v)
		filters.Action = &action
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

	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	writeJSON(w, http.StatusOK, entries)
}
