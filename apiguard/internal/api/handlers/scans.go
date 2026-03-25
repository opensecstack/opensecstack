package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/db"
	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/reporter"
	"github.com/opensecstack/apiguard/internal/scanner"
)

// Scans handles scan-related API endpoints.
type Scans struct {
	logger  zerolog.Logger
	db      *db.DB
	scanner *scanner.Scanner
}

// NewScans creates a new Scans handler.
func NewScans(logger zerolog.Logger, database *db.DB, sc *scanner.Scanner) *Scans {
	return &Scans{
		logger:  logger.With().Str("handler", "scans").Logger(),
		db:      database,
		scanner: sc,
	}
}

// createScanRequest is the JSON body for POST /api/v1/scans.
type createScanRequest struct {
	SpecURL  string   `json:"spec_url"`
	SpecPath string   `json:"spec_path"`
	Target   string   `json:"target"`
	Modules  []string `json:"modules"`
	AuthType string   `json:"auth_type"`
	AuthToken string  `json:"auth_token"`
	AuthHeader string `json:"auth_header"`
}

// Create handles POST /api/v1/scans.
func (s *Scans) Create(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	if req.SpecURL == "" && req.SpecPath == "" {
		writeError(w, http.StatusUnprocessableEntity, "spec_url or spec_path is required")
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusUnprocessableEntity, "target is required")
		return
	}

	scan := &db.Scan{
		TargetURL: req.Target,
		Status:    db.ScanStatusPending,
		Modules:   req.Modules,
	}
	if req.SpecURL != "" {
		scan.SpecURL = sql.NullString{String: req.SpecURL, Valid: true}
	}
	if req.AuthType != "" {
		scan.AuthType = sql.NullString{String: req.AuthType, Valid: true}
	}

	if err := s.db.CreateScan(r.Context(), scan); err != nil {
		s.logger.Error().Err(err).Msg("failed to create scan")
		writeError(w, http.StatusInternalServerError, "failed to create scan")
		return
	}

	scanID := scan.ID

	// Build scanner request.
	scanReq := scanner.ScanRequest{
		SpecPath: req.SpecPath,
		Target:   req.Target,
		Modules:  req.Modules,
		Auth: scanner.AuthConfig{
			Token:  req.AuthToken,
			Type:   req.AuthType,
			Header: req.AuthHeader,
		},
	}
	if req.SpecURL != "" && req.SpecPath == "" {
		scanReq.SpecPath = req.SpecURL
	}

	// Launch scan in background using a detached context so it outlives the request.
	go func() {
		bgCtx := context.Background()

		if err := s.db.UpdateScanStatus(bgCtx, scanID, db.ScanStatusRunning); err != nil {
			s.logger.Error().Err(err).Str("scan_id", scanID.String()).Msg("failed to set scan status to running")
		}

		result, err := s.scanner.Run(bgCtx, scanReq)
		if err != nil {
			s.logger.Error().Err(err).Str("scan_id", scanID.String()).Msg("scan failed")
			if statusErr := s.db.UpdateScanStatus(bgCtx, scanID, db.ScanStatusFailed); statusErr != nil {
				s.logger.Error().Err(statusErr).Str("scan_id", scanID.String()).Msg("failed to set scan status to failed")
			}
			return
		}

		// Persist findings.
		if len(result.Findings) > 0 {
			dbFindings := make([]db.Finding, 0, len(result.Findings))
			for _, f := range result.Findings {
				dbf := db.Finding{
					ScanID:         scanID,
					OwaspID:        f.OWASPId,
					ModuleID:       f.ModuleID,
					Title:          f.Title,
					Description:    f.Description,
					Severity:       db.FindingSeverity(f.Severity),
					CVSSScore:      f.CVSSScore,
					EndpointPath:   f.EndpointPath,
					EndpointMethod: f.EndpointMethod,
					Remediation:    sql.NullString{String: f.Remediation, Valid: f.Remediation != ""},
				}
				if f.CVSSVector != "" {
					dbf.CVSSVector = sql.NullString{String: f.CVSSVector, Valid: true}
				}
				if f.Evidence.Request != "" {
					dbf.EvidenceRequest = sql.NullString{String: f.Evidence.Request, Valid: true}
				}
				if f.Evidence.Response != "" {
					dbf.EvidenceResponse = sql.NullString{String: f.Evidence.Response, Valid: true}
				}
				if len(f.Evidence.Detail) > 0 {
					if b, err := json.Marshal(f.Evidence.Detail); err == nil {
						dbf.EvidenceJSON = b
					}
				}
				dbFindings = append(dbFindings, dbf)
			}

			if err := s.db.CreateFindings(bgCtx, dbFindings); err != nil {
				s.logger.Error().Err(err).Str("scan_id", scanID.String()).Msg("failed to persist findings")
			}
		}

		// Update summary counts.
		summary := db.ScanSummary{
			TotalFindings: result.Summary.TotalFindings,
			CriticalCount: result.Summary.Critical,
			HighCount:     result.Summary.High,
			MediumCount:   result.Summary.Medium,
			LowCount:      result.Summary.Low,
			InfoCount:     result.Summary.Info,
		}
		if err := s.db.UpdateScanSummary(bgCtx, scanID, summary); err != nil {
			s.logger.Error().Err(err).Str("scan_id", scanID.String()).Msg("failed to update scan summary")
		}

		if err := s.db.UpdateScanStatus(bgCtx, scanID, db.ScanStatusCompleted); err != nil {
			s.logger.Error().Err(err).Str("scan_id", scanID.String()).Msg("failed to set scan status to completed")
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id":     scanID.String(),
		"status": string(db.ScanStatusPending),
	})
}

// listScansResponse wraps paginated scan results.
type listScansResponse struct {
	Data    []db.Scan `json:"data"`
	Total   int       `json:"total"`
	Page    int       `json:"page"`
	PerPage int       `json:"per_page"`
}

// List handles GET /api/v1/scans.
func (s *Scans) List(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r, 1, 20, 100)
	offset := (page - 1) * perPage

	scans, total, err := s.db.ListScans(r.Context(), perPage, offset)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to list scans")
		writeError(w, http.StatusInternalServerError, "failed to list scans")
		return
	}

	// Apply optional status filter in-process (DB layer has no status filter param).
	if statusFilter := r.URL.Query().Get("status"); statusFilter != "" {
		filtered := scans[:0]
		for _, sc := range scans {
			if string(sc.Status) == statusFilter {
				filtered = append(filtered, sc)
			}
		}
		scans = filtered
	}

	if scans == nil {
		scans = []db.Scan{}
	}

	resp := listScansResponse{
		Data:    scans,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	writeJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/scans/{id}.
func (s *Scans) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, r, "id")
	if !ok {
		return
	}

	scan, err := s.db.GetScan(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to get scan")
		writeError(w, http.StatusInternalServerError, "failed to get scan")
		return
	}

	writeJSON(w, http.StatusOK, scan)
}

// Findings handles GET /api/v1/scans/{id}/findings.
func (s *Scans) Findings(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, r, "id")
	if !ok {
		return
	}

	page, perPage := parsePagination(r, 1, 20, 100)
	offset := (page - 1) * perPage

	q := r.URL.Query()
	filters := db.FindingFilters{ScanID: &id}
	if sev := q.Get("severity"); sev != "" {
		s := db.FindingSeverity(sev)
		filters.Severity = &s
	}
	if st := q.Get("status"); st != "" {
		s := db.FindingStatus(st)
		filters.Status = &s
	}

	findings, total, err := s.db.ListFindings(r.Context(), filters, perPage, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to list findings for scan")
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

// Report handles GET /api/v1/scans/{id}/report.
func (s *Scans) Report(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, r, "id")
	if !ok {
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	format = strings.ToLower(format)

	scan, err := s.db.GetScan(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to get scan for report")
		writeError(w, http.StatusInternalServerError, "failed to get scan")
		return
	}

	// Fetch all findings for the scan (no pagination — report contains all).
	dbFindings, _, err := s.db.ListFindingsByScan(r.Context(), id, 1000, 0)
	if err != nil {
		s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to get findings for report")
		writeError(w, http.StatusInternalServerError, "failed to get findings")
		return
	}

	// Map DB findings to domain findings.
	domainFindings := make([]domain.Finding, 0, len(dbFindings))
	for _, f := range dbFindings {
		df := domain.Finding{
			ID:             f.ID.String(),
			ScanID:         f.ScanID.String(),
			OWASPId:        f.OwaspID,
			ModuleID:       f.ModuleID,
			Title:          f.Title,
			Description:    f.Description,
			Severity:       domain.Severity(f.Severity),
			CVSSScore:      f.CVSSScore,
			EndpointPath:   f.EndpointPath,
			EndpointMethod: f.EndpointMethod,
			Status:         domain.FindingStatus(f.Status),
			Evidence: domain.Evidence{
				Request:  f.EvidenceRequest.String,
				Response: f.EvidenceResponse.String,
			},
		}
		if f.CVSSVector.Valid {
			df.CVSSVector = f.CVSSVector.String
		}
		if f.Remediation.Valid {
			df.Remediation = f.Remediation.String
		}
		domainFindings = append(domainFindings, df)
	}

	result := &domain.ScanResult{
		ID:     scan.ID.String(),
		Status: domain.ScanStatus(scan.Status),
		Target: scan.TargetURL,
		Findings: domainFindings,
		Summary: domain.ScanSummary{
			TotalFindings: scan.TotalFindings,
			Critical:      scan.CriticalCount,
			High:          scan.HighCount,
			Medium:        scan.MediumCount,
			Low:           scan.LowCount,
			Info:          scan.InfoCount,
		},
	}
	if scan.SpecHash.Valid {
		result.SpecHash = scan.SpecHash.String
	}
	if scan.StartedAt.Valid {
		result.StartedAt = scan.StartedAt.Time
	}
	if scan.CompletedAt.Valid {
		result.CompletedAt = scan.CompletedAt.Time
	}
	if scan.ErrorMessage.Valid {
		result.Error = scan.ErrorMessage.String
	}

	rep, err := reporter.New(format)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	data, err := rep.Generate(result)
	if err != nil {
		s.logger.Error().Err(err).Str("scan_id", id.String()).Str("format", format).Msg("failed to generate report")
		writeError(w, http.StatusInternalServerError, "failed to generate report")
		return
	}

	contentType := reportContentType(format)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// Delete handles DELETE /api/v1/scans/{id}.
func (s *Scans) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, r, "id")
	if !ok {
		return
	}

	if err := s.db.DeleteScan(r.Context(), id); err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to delete scan")
		writeError(w, http.StatusInternalServerError, "failed to delete scan")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// reportContentType maps a report format to its MIME type.
func reportContentType(format string) string {
	switch format {
	case "sarif":
		return "application/sarif+json"
	case "html":
		return "text/html; charset=utf-8"
	default:
		return "application/json"
	}
}

// parseUUID extracts and parses a UUID URL parameter.
// It writes an error response and returns false on failure.
func parseUUID(w http.ResponseWriter, r *http.Request, param string) (uuid.UUID, bool) {
	raw := chi.URLParam(r, param)
	if raw == "" {
		writeError(w, http.StatusBadRequest, param+" is required")
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid "+param+": must be a valid UUID")
		return uuid.UUID{}, false
	}
	return id, true
}

// parsePagination reads page and per_page query params with sensible defaults.
func parsePagination(r *http.Request, defaultPage, defaultPerPage, maxPerPage int) (page, perPage int) {
	q := r.URL.Query()

	page = defaultPage
	if v := q.Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}

	perPage = defaultPerPage
	if v := q.Get("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			perPage = n
		}
	}
	if perPage > maxPerPage {
		perPage = maxPerPage
	}

	return page, perPage
}

// isNotFound returns true when the error message signals a "not found" condition
// (as returned by the db layer which embeds "not found" in the error string).
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") || errors.Is(err, sql.ErrNoRows)
}

// writeJSON encodes v as JSON and writes it with the given HTTP status code.
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   http.StatusText(code),
		"message": message,
	})
}

func notImplemented(w http.ResponseWriter, resource string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "not_implemented",
		"message": resource + " endpoint is not yet implemented",
	})
}
