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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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
	metaJSON, _ := json.Marshal(meta) //nolint:errcheck // meta is always a literal map of JSON-safe types built by call sites in this package
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

// pendingApprovalTTL bounds how long a scan's ephemeral request details (the
// spec/target/auth config needed to actually launch it — never persisted to
// the database, see migrations/001_create_scans.up.sql's "no secrets stored"
// comment) are held in memory awaiting a second approver. After this window,
// an approval attempt returns 410 Gone and the requester must recreate the
// scan. This is an intentional, documented limitation of holding approval
// state in-process rather than persisting scan secrets: it does not survive a
// server restart and does not work across a horizontally-scaled fleet of
// apiguard instances that don't share process memory. Acceptable for the
// current scope; a future iteration could move to a short-lived, encrypted
// server-side credential reference instead of raw secrets.
const pendingApprovalTTL = 24 * time.Hour

// pendingScanRequest holds the scanner request details for a scan awaiting
// second-approver sign-off, in memory only. actorToken is the Operator's own
// sinauth bearer token captured at request time — kept in-process alongside
// the rest of the ephemeral request (never persisted, same as req's own
// target-auth secrets) so that if approval happens before it expires, the
// Kerkese submitted to CITADEL at approval time carries the Operator's real
// token, not an empty/fabricated one.
type pendingScanRequest struct {
	req        createScanRequest
	actorToken string
	createdAt  time.Time
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
	scanWg         sync.WaitGroup  // tracks in-flight scan goroutines for graceful shutdown

	pendingMu   sync.Mutex
	pendingReqs map[uuid.UUID]pendingScanRequest // scans awaiting a second approver
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

// WaitScans blocks until all in-flight scan goroutines have finished. It
// should be called during server shutdown after the HTTP server has stopped
// accepting new requests, so that no new goroutines are started.
func (s *Scans) WaitScans() {
	s.scanWg.Wait()
}

// rememberPendingRequest stores the ephemeral scanner request (and the
// Operator's own bearer token) for a scan that is now awaiting a second
// approver.
func (s *Scans) rememberPendingRequest(id uuid.UUID, req createScanRequest, actorToken string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pendingReqs == nil {
		s.pendingReqs = make(map[uuid.UUID]pendingScanRequest)
	}
	s.sweepExpiredPendingLocked()
	s.pendingReqs[id] = pendingScanRequest{req: req, actorToken: actorToken, createdAt: time.Now()}
}

// takePendingRequest atomically retrieves and removes a scan's pending
// request. found is false if there is none (never stored, already consumed,
// or expired).
func (s *Scans) takePendingRequest(id uuid.UUID) (req createScanRequest, actorToken string, found bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	s.sweepExpiredPendingLocked()
	p, ok := s.pendingReqs[id]
	if !ok {
		return createScanRequest{}, "", false
	}
	delete(s.pendingReqs, id)
	return p.req, p.actorToken, true
}

// deletePendingRequest discards a scan's pending request without returning
// it (used when an approval request is rejected).
func (s *Scans) deletePendingRequest(id uuid.UUID) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	delete(s.pendingReqs, id)
}

// sweepExpiredPendingLocked removes entries older than pendingApprovalTTL.
// Callers must hold pendingMu.
func (s *Scans) sweepExpiredPendingLocked() {
	cutoff := time.Now().Add(-pendingApprovalTTL)
	for k, v := range s.pendingReqs {
		if v.createdAt.Before(cutoff) {
			delete(s.pendingReqs, k)
		}
	}
}

// parseTrustedProxies converts config CIDR strings to net.IPNet values.
// It delegates to the canonical implementation in the middleware package.
func parseTrustedProxies(cfg *config.Config) []*net.IPNet {
	if cfg == nil {
		return nil
	}
	return middleware.ParseTrustedProxyCIDRs(cfg.RateLimit.TrustedProxies)
}

// createScanRequest is the JSON body for POST /api/v1/scans.
type createScanRequest struct {
	SpecURL    string   `json:"spec_url"`
	SpecPath   string   `json:"spec_path"`
	Target     string   `json:"target"`
	Modules    []string `json:"modules"`
	AuthType   string   `json:"auth_type"`
	AuthToken  string   `json:"auth_token"`
	AuthHeader string   `json:"auth_header"`
}

// Create handles POST /api/v1/scans.
func (s *Scans) Create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024) // 1 MB
	var req createScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		s.logger.Error().Err(err).Msg("JSON decode error")
		writeError(w, http.StatusBadRequest, "invalid JSON body")
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

	// A-M2: Validate target URL — only scheme + host checks; no SSRF DNS lookup
	// because the target is an intentional endpoint under test.
	if err := validateTarget(req.Target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid target: "+err.Error())
		return
	}

	// A-H3: Validate spec_path to prevent arbitrary filesystem reads.
	if req.SpecPath != "" {
		allowedDir := os.TempDir()
		clean := filepath.Clean(req.SpecPath)
		if !strings.HasPrefix(clean, allowedDir+string(filepath.Separator)) {
			writeError(w, http.StatusBadRequest, "invalid spec_path")
			return
		}
	}

	// C4: Validate spec_url against SSRF before storing or fetching.
	if req.SpecURL != "" {
		if err := validateSpecURL(r.Context(), req.SpecURL); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}

	// requireApproval gates whether this scan needs a genuine, distinct second
	// authenticated user to sign off before it runs (see Approve/Reject below)
	// instead of launching immediately with CITADEL's placeholder Verifier.
	// Default (config off) preserves today's behavior exactly.
	requireApproval := s.cfg != nil && s.cfg.Citadel.RequireApproval

	scan := &db.Scan{
		TargetURL: req.Target,
		Status:    db.ScanStatusPending,
		Modules:   req.Modules,
	}
	if requireApproval {
		scan.Status = db.ScanStatusPendingApproval
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

	if requireApproval {
		// Real Operator identity — the authenticated caller, same source used
		// throughout this handler. The endpoint sits behind the JWT-protected
		// router group, so claims are always present in production; the
		// fallback only matters for direct unit-test calls to this handler.
		actorUserID := "unauthenticated"
		var actorToken string
		if claims, ok := middleware.ClaimsFromContext(r.Context()); ok && claims.Sub != "" {
			actorUserID = claims.Sub
			actorToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}

		if _, err := s.db.CreateScanApproval(r.Context(), scanID, actorUserID); err != nil {
			s.logger.Error().Err(err).Str("scan_id", scanID.String()).Msg("failed to create scan approval request")
			writeError(w, http.StatusInternalServerError, "failed to create scan approval request")
			return
		}
		// The scanner request (including any target auth secrets, which are
		// never persisted — see migrations/001_create_scans.up.sql) and the
		// Operator's own bearer token are held in memory only until a second
		// approver decides it; see pendingApprovalTTL.
		s.rememberPendingRequest(scanID, req, actorToken)

		s.auditLog(r.Context(), db.AuditActionScanApprovalRequested, "scans", &scanID,
			middleware.ClientIPFromRequest(r, s.trustedProxies), r.UserAgent(),
			map[string]interface{}{"requested_by": actorUserID, "target": req.Target})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck // best-effort write after headers already sent
			"id":     scanID.String(),
			"status": string(db.ScanStatusPendingApproval),
			"message": "this scan requires approval from a different authenticated user before it runs — " +
				"see POST /api/v1/scans/{id}/approve",
		})
		return
	}

	// CITADEL governance check: evaluate the scan against MARSHAL before launching.
	// A REFUSE or HARD_STOP outcome blocks the scan regardless of dry_run config —
	// dry_run is set on the Kerkese itself, so CITADEL decides whether to enforce.
	if s.citadel != nil && s.cfg != nil {
		// Actor = the real authenticated caller (sinauth sub), same identity
		// source already used by auditLog above. ActorToken forwards the
		// caller's own bearer token so CITADEL can verify it directly against
		// sinauth — see citadel adrs/005-sinauth-identity-bridge.md.
		//
		// Known gap, not silently papered over: apiguard has no real
		// second-approver flow for scan initiation, so Verifier is a fixed
		// system placeholder (never equal to Actor, so it doesn't trip Gate
		// 3's NDS_SAME_IDENTITY check) rather than a genuine second person.
		// VerifierToken is left empty; CITADEL treats that as a soft-mode
		// warning today (citadel.enforce_signatures=false), not a block.
		// Building real two-person approval for scan initiation is a
		// separate product change, tracked, not fabricated here.
		actorUserID := "unauthenticated"
		var actorToken string
		if claims, ok := middleware.ClaimsFromContext(r.Context()); ok && claims.Sub != "" {
			actorUserID = claims.Sub
			actorToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}

		k := &citadel.Kerkese{
			KerkeseVersion: "1.0",
			TsUTC:          time.Now().UTC(),
			ProjectID:      s.cfg.Citadel.ProjectID,
			ExecutionID:    scanID,
			Action: citadel.KerkeseAction{
				Type:        "deploy_change",
				Description: "APIGuard security scan: " + req.Target,
				ChangeID:    scanID.String(),
			},
			Actor:    citadel.KerkeseActor{UserID: actorUserID, Role: "group_sig_operator"},
			Verifier: citadel.KerkeseVerifier{UserID: "apiguard-system-verifier", Role: "group_sig_verifier"},
			Evidence: citadel.KerkeseEvidence{
				ChangeID: scanID.String(),
				Extra: map[string]any{
					"target_url": req.Target,
					"modules":    req.Modules,
				},
			},
			SoD:        citadel.KerkeseSoD{OperatorUserID: actorUserID, VerifierUserID: "apiguard-system-verifier"},
			DryRun:     s.cfg.Citadel.DryRun,
			ActorToken: actorToken,
		}
		decision, evalErr := s.citadel.EvaluateScan(r.Context(), k)
		if evalErr != nil {
			// EvaluateScan always returns a non-nil Decision alongside a
			// non-nil error (except when the client is disabled, in
			// which case both are nil and there's nothing to check
			// below), synthesized per s.citadel's FailMode (fail-closed
			// / HARD_STOP by default — see internal/citadel.FailMode).
			s.logger.Warn().Err(evalErr).Str("scan_id", scanID.String()).Msg("CITADEL marshal evaluate failed — applying configured fail-mode")
		}
		if decision != nil && !decision.Allowed() {
			reasons := decision.Reasons
			if len(reasons) == 0 {
				reasons = []string{"CITADEL governance check rejected this scan"}
			}
			writeError(w, http.StatusForbidden, strings.Join(reasons, "; "))
			return
		}
	}

	// Launch scan in background using a context derived from the server shutdown
	// context so the goroutine is cancelled on SIGTERM rather than leaking.
	s.scanWg.Add(1)
	go s.launchScan(scanID, req)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck // best-effort write after headers already sent
		"id":     scanID.String(),
		"status": string(db.ScanStatusPending),
	})
}

// launchScan runs a scan to completion in the background: downloads/loads the
// spec, executes the scanner, persists findings and summary, and emits WORM
// and audit events along the way. It is invoked both by Create() (immediate
// launch, no approval required) and by Approve() (after a genuine second
// approver has signed off). Callers must have already called s.scanWg.Add(1)
// before starting this as a goroutine.
func (s *Scans) launchScan(scanID uuid.UUID, req createScanRequest) {
	defer s.scanWg.Done()

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

	bgCtx := s.shutdownCtx

	// A-H2: track whether the scan reached a terminal status so the deferred
	// cleanup can mark it failed if an unexpected exit occurs.
	// Use context.Background() with a short timeout so the cleanup can still
	// run even if the server shutdown context has already been cancelled.
	completed := false
	defer func() {
		if !completed {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if dbErr := s.db.UpdateScanStatus(cleanCtx, scanID, db.ScanStatusFailed); dbErr != nil {
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

	// WORM: immutable record of scan start.
	if s.citadel != nil && s.cfg != nil {
		projectID := s.cfg.Citadel.ProjectID
		_, _, wormErr := s.citadel.EmitWORM(bgCtx, "apiguard", "scan.started", projectID, map[string]any{
			"scan_id":    scanID.String(),
			"target_url": req.Target,
			"modules":    req.Modules,
		})
		if wormErr != nil {
			s.logger.Warn().Err(wormErr).Str("scan_id", scanID.String()).Msg("CITADEL WORM emit scan.started failed")
		}
	}

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

	// WORM: immutable record of scan completion with finding summary.
	if s.citadel != nil && s.cfg != nil {
		projectID := s.cfg.Citadel.ProjectID

		// Emit one WORM event per CRITICAL finding with NIS2 measure code.
		for _, f := range result.Findings {
			if strings.EqualFold(string(f.Severity), "critical") {
				nis2Code := citadel.NIS2Measure[f.OWASPId]
				_, _, wormErr := s.citadel.EmitWORM(bgCtx, "apiguard", "scan.critical_finding", projectID, map[string]any{
					"scan_id":      scanID.String(),
					"owasp_id":     f.OWASPId,
					"title":        f.Title,
					"endpoint":     f.EndpointPath,
					"method":       f.EndpointMethod,
					"nis2_measure": nis2Code,
				})
				if wormErr != nil {
					s.logger.Warn().Err(wormErr).Str("scan_id", scanID.String()).Str("owasp_id", f.OWASPId).Msg("CITADEL WORM emit scan.critical_finding failed")
				}
			}
		}

		_, _, wormErr := s.citadel.EmitWORM(bgCtx, "apiguard", "scan.completed", projectID, map[string]any{
			"scan_id":        scanID.String(),
			"target_url":     req.Target,
			"total_findings": summary.TotalFindings,
			"critical":       summary.CriticalCount,
			"high":           summary.HighCount,
			"medium":         summary.MediumCount,
			"low":            summary.LowCount,
		})
		if wormErr != nil {
			s.logger.Warn().Err(wormErr).Str("scan_id", scanID.String()).Msg("CITADEL WORM emit scan.completed failed")
		}
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
}

// rejectScanRequest is the optional JSON body for POST /api/v1/scans/{id}/reject.
type rejectScanRequest struct {
	Reason string `json:"reason"`
}

// scanApprovalActionResponse is the response body for Approve/Reject.
type scanApprovalActionResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// approvalCitadelKerkese builds the Kerkese submitted to CITADEL MARSHAL when
// a real second approver decides on a pending scan. Unlike the placeholder
// used in Create() when approval is not required, both Actor and Verifier
// here are genuine, distinct sinauth UserIDs, and — as long as the Operator's
// token captured at request time hasn't expired — both ActorToken and
// VerifierToken are real, live-verifiable bearer tokens too.
func (s *Scans) approvalCitadelKerkese(scanID uuid.UUID, requestedBy, actorToken, approverUserID, approverToken string, req createScanRequest) *citadel.Kerkese {
	return &citadel.Kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Now().UTC(),
		ProjectID:      s.cfg.Citadel.ProjectID,
		ExecutionID:    scanID,
		Action: citadel.KerkeseAction{
			Type:        "deploy_change",
			Description: "APIGuard security scan: " + req.Target,
			ChangeID:    scanID.String(),
		},
		Actor:    citadel.KerkeseActor{UserID: requestedBy, Role: "group_sig_operator"},
		Verifier: citadel.KerkeseVerifier{UserID: approverUserID, Role: "group_sig_verifier"},
		Evidence: citadel.KerkeseEvidence{
			ChangeID: scanID.String(),
			Extra: map[string]any{
				"target_url": req.Target,
				"modules":    req.Modules,
			},
		},
		SoD:    citadel.KerkeseSoD{OperatorUserID: requestedBy, VerifierUserID: approverUserID},
		DryRun: s.cfg.Citadel.DryRun,
		// ActorToken is the Operator's own bearer token, captured at scan
		// creation time and held in memory only (never persisted to the
		// database — see migrations/001_create_scans.up.sql's "no secrets
		// stored" comment) until this approval. It is the Operator's real
		// token, not a placeholder — but if a lot of time passed between
		// request and approval it may have since expired, in which case
		// Gate 1/Gate 3's AuthN token checks for the Operator WARN rather
		// than PASS. That is a known, soft-gated limitation
		// (citadel.enforce_signatures is false), not silently papered over —
		// see the design report for this feature.
		ActorToken: actorToken,
		// VerifierToken is the approver's own bearer token, forwarded live
		// from their own request — CITADEL verifies it directly against
		// sinauth, proving the Verifier's real, independently-authenticated
		// identity (see adrs/005-sinauth-identity-bridge.md).
		VerifierToken: approverToken,
	}
}

// Approve handles POST /api/v1/scans/{id}/approve. A genuine, distinct second
// authenticated user (the Verifier) signs off on a scan that is pending
// approval, satisfying CITADEL Gate 3 Separation-of-Duties (NDS) with two
// real, independently sinauth-authenticated identities — never a placeholder,
// never a token handed over out-of-band by the requester.
func (s *Scans) Approve(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, r, "id")
	if !ok {
		return
	}

	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "authentication required to approve a scan")
		return
	}
	approverUserID := claims.Sub

	approval, err := s.db.GetScanApprovalByScanID(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "no pending approval found for this scan")
			return
		}
		s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to load scan approval")
		writeError(w, http.StatusInternalServerError, "failed to load scan approval")
		return
	}

	if approval.Status != db.ApprovalStatusPending {
		writeError(w, http.StatusConflict, "this scan approval has already been "+string(approval.Status))
		return
	}

	// Separation of Duties: the Verifier must be a genuinely different real
	// identity than the Operator who requested the scan. CITADEL's Gate 3 NDS
	// HARD_STOPs unconditionally on same-identity — this endpoint must never
	// let one person satisfy both roles, so it is checked here too, before
	// ever building a Kerkese.
	if approverUserID == approval.RequestedBy {
		writeError(w, http.StatusForbidden,
			"the approver must be a different authenticated user than the one who requested the scan (separation of duties)")
		return
	}

	req, actorToken, found := s.takePendingRequest(id)
	if !found {
		// The ephemeral request details needed to actually launch the scan
		// (never persisted — see pendingApprovalTTL) are gone: either the
		// server restarted since the scan was requested, or the approval
		// window (pendingApprovalTTL) expired. Terminal state — the requester
		// must create a new scan.
		reason := "original scan request is no longer available (server restart or approval window expired)"
		if err := s.db.RejectScanApproval(r.Context(), id, approverUserID, reason); err != nil {
			s.logger.Warn().Err(err).Str("scan_id", id.String()).Msg("failed to record expired scan approval")
		}
		if err := s.db.UpdateScanError(r.Context(), id, "scan approval expired: "+reason); err != nil {
			s.logger.Warn().Err(err).Str("scan_id", id.String()).Msg("failed to update scan status after approval expiry")
		}
		s.auditLog(r.Context(), db.AuditActionScanApprovalRejected, "scans", &id,
			middleware.ClientIPFromRequest(r, s.trustedProxies), r.UserAgent(),
			map[string]interface{}{"approver": approverUserID, "reason": reason})
		writeError(w, http.StatusGone,
			"scan was approved too late — the original request details are no longer available; create a new scan")
		return
	}

	approverToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	if s.citadel != nil && s.cfg != nil {
		k := s.approvalCitadelKerkese(id, approval.RequestedBy, actorToken, approverUserID, approverToken, req)
		decision, evalErr := s.citadel.EvaluateScan(r.Context(), k)
		if evalErr != nil {
			s.logger.Warn().Err(evalErr).Str("scan_id", id.String()).Msg("CITADEL marshal evaluate failed on approval — proceeding")
		} else if decision != nil && (decision.Outcome == citadel.OutcomeRefuse || decision.Outcome == citadel.OutcomeHardStop) {
			reasons := decision.Reasons
			if len(reasons) == 0 {
				reasons = []string{"CITADEL governance check rejected this approval"}
			}
			reasonStr := strings.Join(reasons, "; ")
			if err := s.db.RejectScanApproval(r.Context(), id, approverUserID, reasonStr); err != nil {
				s.logger.Warn().Err(err).Str("scan_id", id.String()).Msg("failed to record CITADEL-rejected scan approval")
			}
			if err := s.db.UpdateScanError(r.Context(), id, "scan rejected by CITADEL governance check: "+reasonStr); err != nil {
				s.logger.Warn().Err(err).Str("scan_id", id.String()).Msg("failed to update scan status after CITADEL rejection")
			}
			s.auditLog(r.Context(), db.AuditActionScanApprovalRejected, "scans", &id,
				middleware.ClientIPFromRequest(r, s.trustedProxies), r.UserAgent(),
				map[string]interface{}{"approver": approverUserID, "reason": reasonStr})
			writeError(w, http.StatusForbidden, reasonStr)
			return
		}
	}

	if err := s.db.ApproveScanApproval(r.Context(), id, approverUserID); err != nil {
		// Lost a race to a concurrent approve/reject on the same scan. Put
		// the pending request back so the current state can still be
		// inspected/retried rather than silently orphaning the scan.
		s.rememberPendingRequest(id, req, actorToken)
		s.logger.Warn().Err(err).Str("scan_id", id.String()).Msg("scan approval race lost")
		writeError(w, http.StatusConflict, "this scan approval was concurrently decided by someone else")
		return
	}

	if err := s.db.UpdateScanStatus(r.Context(), id, db.ScanStatusPending); err != nil {
		s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to set scan status to pending after approval")
	}

	s.auditLog(r.Context(), db.AuditActionScanApprovalApproved, "scans", &id,
		middleware.ClientIPFromRequest(r, s.trustedProxies), r.UserAgent(),
		map[string]interface{}{"approved_by": approverUserID, "requested_by": approval.RequestedBy})

	s.scanWg.Add(1)
	go s.launchScan(id, req)

	writeJSON(w, http.StatusOK, scanApprovalActionResponse{ID: id.String(), Status: string(db.ScanStatusPending)})
}

// Reject handles POST /api/v1/scans/{id}/reject. A genuine, distinct second
// authenticated user declines a pending scan request; the scan never runs.
func (s *Scans) Reject(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, r, "id")
	if !ok {
		return
	}

	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "authentication required to reject a scan")
		return
	}
	rejectorUserID := claims.Sub

	approval, err := s.db.GetScanApprovalByScanID(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "no pending approval found for this scan")
			return
		}
		s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to load scan approval")
		writeError(w, http.StatusInternalServerError, "failed to load scan approval")
		return
	}

	if approval.Status != db.ApprovalStatusPending {
		writeError(w, http.StatusConflict, "this scan approval has already been "+string(approval.Status))
		return
	}

	if rejectorUserID == approval.RequestedBy {
		writeError(w, http.StatusForbidden,
			"the reviewer must be a different authenticated user than the one who requested the scan (separation of duties)")
		return
	}

	var body rejectScanRequest
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 4*1024)).Decode(&body) //nolint:errcheck // best-effort; reason is optional
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = "rejected by reviewer"
	}

	if err := s.db.RejectScanApproval(r.Context(), id, rejectorUserID, reason); err != nil {
		s.logger.Warn().Err(err).Str("scan_id", id.String()).Msg("scan rejection race lost")
		writeError(w, http.StatusConflict, "this scan approval was concurrently decided by someone else")
		return
	}
	if err := s.db.UpdateScanError(r.Context(), id, "scan rejected: "+reason); err != nil {
		s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to update scan status after rejection")
	}
	s.deletePendingRequest(id)

	s.auditLog(r.Context(), db.AuditActionScanApprovalRejected, "scans", &id,
		middleware.ClientIPFromRequest(r, s.trustedProxies), r.UserAgent(),
		map[string]interface{}{"rejected_by": rejectorUserID, "requested_by": approval.RequestedBy, "reason": reason})

	writeJSON(w, http.StatusOK, scanApprovalActionResponse{ID: id.String(), Status: string(db.ScanStatusFailed)})
}

// GetApproval handles GET /api/v1/scans/{id}/approval — returns the current
// two-person approval state for a scan (who requested it, who decided it and
// how, if anyone yet).
func (s *Scans) GetApproval(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(w, r, "id")
	if !ok {
		return
	}

	approval, err := s.db.GetScanApprovalByScanID(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "no approval record for this scan")
			return
		}
		s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to load scan approval")
		writeError(w, http.StatusInternalServerError, "failed to load scan approval")
		return
	}

	writeJSON(w, http.StatusOK, approval)
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

	// A-M3: Validate status filter against known scan status values.
	if statusFilter != "" {
		switch db.ScanStatus(statusFilter) {
		case db.ScanStatusPending, db.ScanStatusPendingApproval, db.ScanStatusRunning, db.ScanStatusCompleted, db.ScanStatusFailed, db.ScanStatusCancelled:
			// valid
		default:
			writeError(w, http.StatusBadRequest, "invalid status value")
			return
		}
	}

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
		switch db.FindingSeverity(sev) {
		case db.FindingSeverityCritical,
			db.FindingSeverityHigh,
			db.FindingSeverityMedium,
			db.FindingSeverityLow,
			db.FindingSeverityInfo:
			s := db.FindingSeverity(sev)
			filters.Severity = &s
		default:
			writeError(w, http.StatusBadRequest, "invalid severity value")
			return
		}
	}
	if st := q.Get("status"); st != "" {
		switch db.FindingStatus(st) {
		case db.FindingStatusOpen, db.FindingStatusConfirmed, db.FindingStatusFalsePositive, db.FindingStatusAccepted, db.FindingStatusFixed:
			s := db.FindingStatus(st)
			filters.Status = &s
		default:
			writeError(w, http.StatusBadRequest, "invalid status value")
			return
		}
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

	// Fetch all findings for the scan in pages to avoid the 1000-row cap.
	var allFindings []db.Finding
	{
		const pageSize = 500
		offset := 0
		for {
			batch, _, err := s.db.ListFindingsByScan(r.Context(), id, pageSize, offset)
			if err != nil {
				s.logger.Error().Err(err).Str("scan_id", id.String()).Msg("failed to get findings for report")
				writeError(w, http.StatusInternalServerError, "failed to get findings")
				return
			}
			allFindings = append(allFindings, batch...)
			if len(batch) < pageSize {
				break
			}
			offset += pageSize
		}
	}

	// Map DB findings to domain findings.
	domainFindings := make([]domain.Finding, 0, len(allFindings))
	for _, f := range allFindings {
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
		ID:       scan.ID.String(),
		Status:   domain.ScanStatus(scan.Status),
		Target:   scan.TargetURL,
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
	if format == "text" {
		filename := fmt.Sprintf("apiguard-report-%s.txt", id.String())
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data) // #nosec G104 G705 -- best-effort write after headers already sent; when format=="html" this is generated by internal/reporter's HTMLReporter using html/template, which auto-escapes all interpolated finding/target data, so XSS via reflected scan content is not possible here
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
	case "text":
		return "text/plain; charset=utf-8"
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
	_ = json.NewEncoder(w).Encode(v) //nolint:errcheck // best-effort write after headers already sent
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck // best-effort write after headers already sent
		"error":   http.StatusText(code),
		"message": message,
	})
}

// writeErrorWithCode writes a JSON error response with an application-level error code.
func writeErrorWithCode(w http.ResponseWriter, httpCode int, message, errCode string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck // best-effort write after headers already sent
		"error": message,
		"code":  errCode,
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

// ssrfSafeClient is a package-level *http.Client used for downloading remote
// OpenAPI specs. It prevents TOCTOU SSRF by re-validating the resolved IP
// inside DialContext (after OS hostname resolution, before connection) and
// blocks redirects entirely so an attacker cannot redirect to an internal
// address after the initial URL has passed validation.
var ssrfSafeClient = func() *http.Client {
	baseDialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("ssrf-safe dial: invalid address %q: %w", addr, err)
			}
			addrs, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("ssrf-safe dial: resolve %q: %w", host, err)
			}
			if len(addrs) == 0 {
				return nil, fmt.Errorf("ssrf-safe dial: no addresses resolved for %q", host)
			}
			// Reject the entire connection if ANY resolved address is in a
			// private/reserved range. Checking only addrs[0] would allow a
			// multi-record response with a private IP at a later index to
			// bypass the SSRF guard after a connection refusal on the first.
			for _, a := range addrs {
				ip := net.ParseIP(a)
				if ip != nil {
					for _, block := range privateIPNets {
						if block.Contains(ip) {
							return nil, fmt.Errorf("ssrf-safe dial: resolved IP %s is in a private/reserved range", a)
						}
					}
				}
			}
			// All addresses passed the SSRF check; attempt each in order and
			// return the first successful connection.
			var lastErr error
			for _, a := range addrs {
				conn, dialErr := baseDialer.DialContext(ctx, network, net.JoinHostPort(a, port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, fmt.Errorf("ssrf-safe dial: could not connect to any address for %q: %w", host, lastErr)
		},
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}()

// validateTarget checks that rawURL is a valid http/https URL with a non-empty
// host. It does not perform DNS resolution or SSRF checks because the target is
// an intentional endpoint under test chosen by the operator.
func validateTarget(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("URL has no hostname")
	}
	return nil
}

// validateSpecURL checks that rawURL uses http/https and does not resolve to a
// private or loopback IP address, preventing SSRF attacks.
// ctx is used for the DNS lookup so that it honours request deadlines and can
// be cancelled (e.g. on server shutdown) rather than blocking for the full OS
// DNS timeout.
func validateSpecURL(ctx context.Context, rawURL string) error {
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
	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
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

	resp, err := ssrfSafeClient.Do(req)
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
	if n == maxBytes {
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
