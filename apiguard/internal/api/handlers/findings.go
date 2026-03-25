package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/db"
)

// Findings handles finding-related API endpoints.
type Findings struct {
	logger zerolog.Logger
	db     *db.DB
}

// NewFindings creates a new Findings handler.
func NewFindings(logger zerolog.Logger, database *db.DB) *Findings {
	return &Findings{
		logger: logger.With().Str("handler", "findings").Logger(),
		db:     database,
	}
}

// List handles GET /api/v1/findings.
func (f *Findings) List(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r, 1, 20, 100)
	offset := (page - 1) * perPage

	q := r.URL.Query()
	filters := db.FindingFilters{}

	if scanIDStr := q.Get("scan_id"); scanIDStr != "" {
		id, err := uuid.Parse(scanIDStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid scan_id: must be a valid UUID")
			return
		}
		filters.ScanID = &id
	}
	if sev := q.Get("severity"); sev != "" {
		s := db.FindingSeverity(sev)
		filters.Severity = &s
	}
	if st := q.Get("status"); st != "" {
		s := db.FindingStatus(st)
		filters.Status = &s
	}
	if owaspID := q.Get("owasp_id"); owaspID != "" {
		filters.OwaspID = &owaspID
	}
	if moduleID := q.Get("module_id"); moduleID != "" {
		filters.ModuleID = &moduleID
	}

	findings, total, err := f.db.ListFindings(r.Context(), filters, perPage, offset)
	if err != nil {
		f.logger.Error().Err(err).Msg("failed to list findings")
		writeError(w, http.StatusInternalServerError, "failed to list findings")
		return
	}

	if findings == nil {
		findings = []db.Finding{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":     findings,
		"total":    total,
		"page":     page,
		"per_page": perPage,
	})
}

// Get handles GET /api/v1/findings/{id}.
func (f *Findings) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, r, "id")
	if !ok {
		return
	}

	finding, err := f.db.GetFinding(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "finding not found")
			return
		}
		f.logger.Error().Err(err).Str("finding_id", id.String()).Msg("failed to get finding")
		writeError(w, http.StatusInternalServerError, "failed to get finding")
		return
	}

	writeJSON(w, http.StatusOK, finding)
}

// updateFindingRequest is the JSON body for PATCH /api/v1/findings/{id}.
type updateFindingRequest struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}

// Update handles PATCH /api/v1/findings/{id}.
func (f *Findings) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, r, "id")
	if !ok {
		return
	}

	var req updateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	// Validate status value.
	switch db.FindingStatus(req.Status) {
	case db.FindingStatusOpen,
		db.FindingStatusConfirmed,
		db.FindingStatusFalsePositive,
		db.FindingStatusAccepted,
		db.FindingStatusFixed:
		// valid
	default:
		writeError(w, http.StatusUnprocessableEntity,
			"status must be one of: open, confirmed, false_positive, accepted, fixed")
		return
	}

	if err := f.db.UpdateFindingStatus(r.Context(), id, db.FindingStatus(req.Status), req.Note); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "finding not found")
			return
		}
		f.logger.Error().Err(err).Str("finding_id", id.String()).Msg("failed to update finding")
		writeError(w, http.StatusInternalServerError, "failed to update finding")
		return
	}

	// Return the updated finding.
	finding, err := f.db.GetFinding(r.Context(), id)
	if err != nil {
		f.logger.Error().Err(err).Str("finding_id", id.String()).Msg("failed to fetch updated finding")
		writeError(w, http.StatusInternalServerError, "failed to fetch updated finding")
		return
	}

	writeJSON(w, http.StatusOK, finding)
}
