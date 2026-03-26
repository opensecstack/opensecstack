package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/citadel"
	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/db"
	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/reporter"
	"github.com/opensecstack/apiguard/internal/scanner"
)

// auditLog appends an audit log entry locally and forwards it to CITADEL.
// Errors are logged as warnings but never returned to callers — audit failures
// must not break normal operations.
func (s *Scans) auditLog(ctx context.Context, action db.AuditAction, resourceType string, resourceID *uuid.UUID, ip, ua string, meta map[string]interface{}) {
	actorID := "system"
	actorType := "system"
	if claims, ok := middleware.ClaimsFromContext(ctx); ok && claims.Sub != "" {
		actorID = claims.Sub
		actorType = "user"
	}
	metaJSON, _ := json.Marshal(meta)
	entry := &db.AuditLog{
		ActorID:      actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Metadata:     metaJSON,
	}
	if ip != "" {
		entry.IPAddress = sql.NullString{String: ip, Valid: true}
	}
	if ua != "" {
		entry.UserAgent = sql.NullString{String: ua, Valid: true}
	}
	if err := s.db.AppendAuditLog(ctx, entry, s.citadel); err != nil {
		ev := s.logger.Warn().Err(err).Str("action", string(action))
		if resourceID != nil {
			ev = ev.Str(resourceType+"_id", resourceID.String())
		}
		ev.Msg("audit log write failed")
	}
}

// Scans handles scan-related API endpoints.
type Scans struct {
	logger         zerolog.Logger
	db             *db.DB
	scanner        *scanner.Scanner
	citadel        *citadel.Client
	cfg            *config.Config
	shutdownCtx    context.Context // cancelled when the server is shutting down
	trustedProxies []*net.IPNet    // parsed from cfg.RateLimit.TrustedProxies
}

// NewScans creates a new Scans handler.
// shutdownCtx should be a context that is cancelled when the server shuts down;
// pass context.Background() only in tests where lifetime tracking is not needed.
func NewScans(logger zerolog.Logger, database *db.DB, sc *scanner.Scanner, shutdownCtx context.Context) *Scans {
	return &Scans{
		logger:      logger.With().Str("handler", "scans").Logger(),
		db:          database,
		scanner:     sc,
		shutdownCtx: shutdownCtx,
	}
}

// NewScansWithCitadel creates a new Scans handler with a CITADEL forwarding client.
// shutdownCtx should be the server's shutdown context; scan goroutines are parented
// to it so they are cancelled when the server receives SIGTERM.
func NewScansWithCitadel(logger zerolog.Logger, database *db.DB, sc *scanner.Scanner, cc *citadel.Client, shutdownCtx context.Context, cfg *config.Config) *Scans {
	return &Scans{
		logger:         logger.With().Str("handler", "scans").Logger(),
		db:             database,
		scanner:        sc,
		citadel:        cc,
		cfg:            cfg,
		shutdownCtx:    shutdownCtx,
		trustedProxies: parseTrustedProxies(cfg),
	}
}

// parseTrustedProxies converts config CIDR strings to net.IPNet values.
func parseTrustedProxies(cfg *config.Config) []*net.IPNet {
	if cfg == nil {
		return nil
	}
	var nets []*net.IPNet
	for _, cidr := range cfg.RateLimit.TrustedProxies {
		if !strings.Contains(cidr, "/") {
			cidr = cidr + "/32"
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}
	return nets
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
	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024) // 1 MB
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

	// C4: Validate spec_url against SSRF before storing or fetching.
	if req.SpecURL != "" {
		if err := validateSpecURL(req.SpecURL); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
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
	s.auditLog(r.Context(), db.AuditActionScanCreated, "scans", &scanID,
		middleware.ClientIPFromRequest(r, s.trustedProxies), r.UserAgent(), map[string]interface{}{"target": req.Target})

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

	// Launch scan in background using a context derived from the server shutdown
	// context so the goroutine is cancelled on SIGTERM rather than leaking.
	go func() {
		bgCtx := s.shutdownCtx

		// M3: track whether the scan reached a terminal status so the deferred
		// cleanup can mark it failed if an unexpected exit occurs.
		completed := false
		defer func() {
			if !completed {
				if dbErr := s.db.UpdateScanStatus(bgCtx, scanID, db.ScanStatusFailed); dbErr != nil {
					s.logger.Error().Err(dbErr).Str("scan_id", scanID.String()).Msg("failed to set scan status to failed in deferred cleanup")
				}
			}
		}()

		// If a spec URL was provided (and no local path), download it to a temp
		// file so the scanner's validateSpecPath can open it as a local file.
		var tempSpecFile string
		if req.SpecURL != "" && req.SpecPath == "" {
			maxSpecSize := 10 // 10 MB default
			if s.cfg != nil && s.cfg.Scanner.MaxSpecSize > 0 {
				maxSpecSize = s.cfg.Scanner.MaxSpecSize
			}
			path, dlErr := downloadSpecToTemp(bgCtx, req.SpecURL, maxSpecSize)
			if dlErr != nil {
				s.logger.Error().Err(dlErr).Str("scan_id", scanID.String()).Str("spec_url", req.SpecURL).Msg("failed to download spec")
				if dbErr := s.db.UpdateScanError(bgCtx, scanID, fmt.Sprintf("failed to download spec: %v", dlErr)); dbErr != nil {
					s.logger.Error().Err(dbErr).Str("scan_id", scanID.String()).Msg("failed to record scan error")
				}
				return
			}
			// M4: remove the temp file inside the goroutine, after the scan completes.
			tempSpecFile = path
			defer os.Remove(tempSpecFile)
			scanReq.SpecPath = tempSpecFile
		}

		if err := s.db.UpdateScanStatus(bgCtx, scanID, db.ScanStatusRunning); err != nil {
			s.logger.Error().Err(err).Str("scan_id", scanID.String()).Msg("failed to set scan status to running")
		}
		s.auditLog(bgCtx, db.AuditActionScanStarted, "scans", &scanID, "", "", nil)

		result, err := s.scanner.Run(bgCtx, scanReq)
		if err != nil {
			s.logger.Error().Err(err).Str("scan_id", scanID.String()).Msg("scan failed")
			if dbErr := s.db.UpdateScanError(bgCtx, scanID, err.Error()); dbErr != nil {
				s.logger.Error().Err(dbErr).Str("scan_id", scanID.String()).Msg("failed to record scan error")
			}
			s.auditLog(bgCtx, db.AuditActionScanFailed, "scans", &scanID, "", "",
				map[string]interface{}{"error": err.Error()})
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
				if dbErr := s.db.UpdateScanError(bgCtx, scanID, "failed to persist findings: "+err.Error()); dbErr != nil {
					s.logger.Error().Err(dbErr).Str("scan_id", scanID.String()).Msg("failed to record scan error")
				}
				s.auditLog(bgCtx, db.AuditActionScanFailed, "scans", &scanID, "", "",
					map[string]interface{}{"error": "failed to persist findings"})
				return
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

		// M3: mark as completed so the deferred handler does not set status to failed.
		completed = true
		if err := s.db.UpdateScanStatus(bgCtx, scanID, db.ScanStatusCompleted); err != nil {
			s.logger.Error().Err(err).Str("scan_id", scanID.String()).Msg("failed to set scan status to completed")
		}

		// Upsert api_spec and link it to this scan if we have a spec hash.
		if result.SpecHash != "" {
			specURL := sql.NullString{}
			if req.SpecURL != "" {
				specURL = sql.NullString{String: req.SpecURL, Valid: true}
			}
			spec := &db.APISpec{
				SpecHash: result.SpecHash,
				SpecURL:  specURL,
				BaseURL:  sql.NullString{String: req.Target, Valid: true},
			}
			if err := s.db.UpsertAPISpec(bgCtx, spec); err != nil {
				s.logger.Warn().Err(err).Str("scan_id", scanID.String()).Msg("failed to upsert api_spec")
			} else {
				if err := s.db.LinkScanAPISpec(bgCtx, scanID, spec.ID); err != nil {
					s.logger.Warn().Err(err).Str("scan_id", scanID.String()).Msg("failed to link api_spec to scan")
				}
				s.auditLog(bgCtx, db.AuditActionSpecParsed, "api_specs", &spec.ID, "", "",
					map[string]interface{}{"spec_hash": result.SpecHash})
			}
		}

		s.auditLog(bgCtx, db.AuditActionScanCompleted, "scans", &scanID, "", "",
			map[string]interface{}{"total_findings": summary.TotalFindings})
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
	statusFilter := r.URL.Query().Get("status")

	scans, total, err := s.db.ListScans(r.Context(), perPage, offset, statusFilter)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to list scans")
		writeError(w, http.StatusInternalServerError, "failed to list scans")
		return
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

	s.auditLog(r.Context(), db.AuditActionReportGenerated, "scans", &id,
		middleware.ClientIPFromRequest(r, s.trustedProxies), r.UserAgent(), map[string]interface{}{"format": format})

	contentType := reportContentType(format)
	w.Header().Set("Content-Type", contentType)
	if format == "pdf" {
		filename := fmt.Sprintf("apiguard-report-%s.pdf", id.String())
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	}
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

	s.auditLog(r.Context(), db.AuditActionScanDeleted, "scans", &id,
		middleware.ClientIPFromRequest(r, s.trustedProxies), r.UserAgent(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// reportContentType maps a report format to its MIME type.
func reportContentType(format string) string {
	switch format {
	case "sarif":
		return "application/sarif+json"
	case "html":
		return "text/html; charset=utf-8"
	case "pdf":
		return "application/pdf"
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

// privateIPNets are the IP ranges that must not be reached via spec_url (SSRF prevention).
var privateIPNets []*net.IPNet

func init() {
	blocks := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
	}
	for _, b := range blocks {
		_, cidr, err := net.ParseCIDR(b)
		if err == nil {
			privateIPNets = append(privateIPNets, cidr)
		}
	}
}

// validateSpecURL checks that rawURL uses http/https and does not resolve to a
// private or loopback IP address, preventing SSRF attacks.
func validateSpecURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid spec_url: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("spec_url scheme must be http or https, got %q", parsed.Scheme)
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("spec_url has no hostname")
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return fmt.Errorf("spec_url hostname resolution failed: %w", err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		for _, block := range privateIPNets {
			if block.Contains(ip) {
				return fmt.Errorf("spec_url resolves to a private/reserved IP address (%s), which is not allowed", addr)
			}
		}
	}
	return nil
}

// downloadSpecToTemp fetches a remote OpenAPI spec URL and writes it to a
// temporary file, returning the file path. The caller is responsible for
// removing the file when done (e.g. with defer os.Remove(path)).
// maxSpecSize is the maximum allowed file size in megabytes.
func downloadSpecToTemp(ctx context.Context, specURL string, maxSpecSize int) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specURL, nil)
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching spec: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("spec URL returned HTTP %d", resp.StatusCode)
	}

	// L1: reject HTML responses — they indicate a login page or error, not a spec.
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(strings.ToLower(ct), "text/html") {
		return "", fmt.Errorf("spec URL returned HTML content, expected YAML or JSON")
	}

	f, err := os.CreateTemp("", "apiguard-spec-*.json")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}

	maxBytes := int64(maxSpecSize) * 1024 * 1024
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("writing spec to temp file: %w", err)
	}
	if n >= maxBytes {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("spec file exceeds maximum size of %d bytes", maxBytes)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("closing temp file: %w", err)
	}

	return f.Name(), nil
}
