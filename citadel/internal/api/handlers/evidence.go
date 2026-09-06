package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/citadel/internal/db"
)

// Compliance Evidence ingestion — the CITADEL side of the NIS2 Compass ->
// CITADEL push pipeline (root CLAUDE.md's SDK-contract table, "Compliance
// Evidence | JSON v1"). See nis2compass/app/citadel_client.py's
// submit_compliance_evidence for the producer side; wire shapes here are
// the contract of record NIS2 Compass's JSON body must match field-for-field
// (see sdk/go/opensecstack.ComplianceEvidence).
//
// This is deliberately NOT routed through MARSHAL: submitting evidence
// isn't a privileged action asking for an authorization verdict (there is
// nothing to REFUSE or HARD_STOP — the caller isn't requesting permission
// to do something risky), it's depositing an audit record. But it IS
// audit-relevant, so per root CLAUDE.md's Governance & Audit section it
// still flows through the WORM chain (AppendWORM) rather than existing as a
// parallel shadow log, and is additionally stored in the queryable
// compliance_evidence table so "what evidence has been submitted for org X,
// assessment Y" is a real, answerable question (WORM alone only proves an
// event happened and is tamper-evident — it is not designed for
// filtered-by-business-key retrieval).

// evidenceStore is the subset of *db.DB required by Evidence.
type evidenceStore interface {
	AppendWORM(ctx context.Context, source, eventType, projectID string, payload []byte, sigOperator, sigVerifier string) (*db.WORMEntry, error)
	InsertComplianceEvidence(ctx context.Context, organisationID, assessmentID, schemaVersion, reportHash string, report []byte, submittedBy string, wormEntryID uuid.UUID) (*db.ComplianceEvidence, error)
	GetComplianceEvidence(ctx context.Context, id uuid.UUID) (*db.ComplianceEvidence, bool, error)
	ListComplianceEvidence(ctx context.Context, organisationID, assessmentID string) ([]*db.ComplianceEvidence, error)
}

// evidenceTokenVerifier is the subset of marshal.TokenVerifier required by
// Evidence (duplicated per-handler rather than importing marshal, matching
// the existing keysTokenVerifier precedent in keys.go).
type evidenceTokenVerifier interface {
	Verify(ctx context.Context, token string) (userID, role string, err error)
}

// evidenceWritableRoles are the roles (of the 5 canonical roles documented
// in root CLAUDE.md's Production Readiness section: admin, operator,
// verifier, viewer, service) permitted to submit new evidence. Mirrors
// irflow/internal/auth/roles.go's canWrite convention (the canonical
// example root CLAUDE.md's RBAC line points to): operators and admins
// produce/change state, service covers machine-to-machine callers like
// NIS2 Compass itself, viewer and verifier are read-only for this
// capability — evidence submission is an assertion of fact, not a
// countersigned decision, so verifier (Separation-of-Duties counterparty
// for privileged actions elsewhere) has no special role here.
var evidenceWritableRoles = map[string]bool{
	"admin":    true,
	"operator": true,
	"service":  true,
}

// Evidence handles POST /api/v1/evidence/submit, GET /api/v1/evidence/{id},
// and GET /api/v1/evidence.
type Evidence struct {
	logger   zerolog.Logger
	store    evidenceStore
	verifier evidenceTokenVerifier
}

// NewEvidence creates an Evidence handler.
func NewEvidence(logger zerolog.Logger, store evidenceStore, verifier evidenceTokenVerifier) *Evidence {
	return &Evidence{logger: logger, store: store, verifier: verifier}
}

// submitEvidenceRequest is the body for POST /api/v1/evidence/submit.
// Field names/JSON tags MUST match sdk/go/opensecstack.SubmitComplianceEvidenceRequest
// exactly — see that type's doc comment.
type submitEvidenceRequest struct {
	ActorToken     string          `json:"actor_token"`
	OrganisationID string          `json:"organisation_id"`
	AssessmentID   string          `json:"assessment_id"`
	SchemaVersion  string          `json:"schema_version"`
	Report         json.RawMessage `json:"report"`
}

// submitEvidenceResponse is returned by POST /api/v1/evidence/submit.
type submitEvidenceResponse struct {
	ID          string    `json:"id"`
	WORMEntryID string    `json:"worm_entry_id"`
	ChainHash   string    `json:"chain_hash"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// evidenceResponse is the JSON shape of a single evidence record returned
// by both the submit and get/list endpoints' payload — mirrors
// sdk/go/opensecstack.ComplianceEvidence.
type evidenceResponse struct {
	ID             string          `json:"id"`
	OrganisationID string          `json:"organisation_id"`
	AssessmentID   string          `json:"assessment_id"`
	SchemaVersion  string          `json:"schema_version"`
	ReportHash     string          `json:"report_hash"`
	Report         json.RawMessage `json:"report"`
	SubmittedBy    string          `json:"submitted_by"`
	WORMEntryID    string          `json:"worm_entry_id"`
	SubmittedAt    time.Time       `json:"submitted_at"`
}

func toEvidenceResponse(e *db.ComplianceEvidence) evidenceResponse {
	return evidenceResponse{
		ID:             e.ID.String(),
		OrganisationID: e.OrganisationID,
		AssessmentID:   e.AssessmentID,
		SchemaVersion:  e.SchemaVersion,
		ReportHash:     e.ReportHash,
		Report:         json.RawMessage(e.Report),
		SubmittedBy:    e.SubmittedBy,
		WORMEntryID:    e.WORMEntryID.String(),
		SubmittedAt:    e.SubmittedAt,
	}
}

// wormEvidencePayload is the JSON payload written into worm_entries for a
// compliance_evidence_submitted event. The full report is embedded (not
// just report_hash) so the WORM chain's TripleHash genuinely covers the
// evidence content, not merely a claim about its hash — matching how
// MARSHAL's gate5 embeds the full Kerkese in its WORM payload rather than a
// summary of it.
type wormEvidencePayload struct {
	OrganisationID string          `json:"organisation_id"`
	AssessmentID   string          `json:"assessment_id"`
	SchemaVersion  string          `json:"schema_version"`
	ReportHash     string          `json:"report_hash"`
	Report         json.RawMessage `json:"report"`
	SubmittedBy    string          `json:"submitted_by"`
}

// Submit handles POST /api/v1/evidence/submit.
//
// AuthN/RBAC: the request must carry a live sinauth bearer token
// (actor_token) that this handler verifies directly — CITADEL has no
// general Authorization-header middleware today (see keys.go's Register for
// the same per-handler-verification precedent), so each handler that needs
// real identity checks it explicitly. The verified role must be one of
// evidenceWritableRoles; anything else (including an unknown/malformed
// role) is rejected with 403 rather than defaulting to allow.
func (e *Evidence) Submit(w http.ResponseWriter, r *http.Request) {
	var req submitEvidenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		e.logger.Error().Err(err).Msg("evidence submit: decode request")
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ActorToken == "" || req.OrganisationID == "" || req.AssessmentID == "" ||
		req.SchemaVersion == "" || len(req.Report) == 0 {
		writeJSONError(w, http.StatusBadRequest, "actor_token, organisation_id, assessment_id, schema_version, and report are required")
		return
	}

	submittedBy, role, err := e.verifier.Verify(r.Context(), req.ActorToken)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "actor_token is not a valid sinauth bearer token")
		return
	}
	if !evidenceWritableRoles[role] {
		writeJSONError(w, http.StatusForbidden, "role is not permitted to submit compliance evidence")
		return
	}

	reportHash := sha256.Sum256(req.Report)
	reportHashHex := hex.EncodeToString(reportHash[:])

	wormPayload, err := json.Marshal(wormEvidencePayload{
		OrganisationID: req.OrganisationID,
		AssessmentID:   req.AssessmentID,
		SchemaVersion:  req.SchemaVersion,
		ReportHash:     reportHashHex,
		Report:         req.Report,
		SubmittedBy:    submittedBy,
	})
	if err != nil {
		// json.Marshal of a struct containing only strings and a
		// json.RawMessage we already successfully decoded cannot realistically
		// fail, but treat it as a real error rather than proceeding with a
		// zero-value payload if it somehow does.
		e.logger.Error().Err(err).Msg("evidence submit: marshal worm payload")
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	wormEntry, err := e.store.AppendWORM(r.Context(), "nis2compass", "compliance_evidence_submitted", "nis2compass", wormPayload, "", "")
	if err != nil {
		e.logger.Error().Err(err).Msg("evidence submit: append worm failed")
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	entry, err := e.store.InsertComplianceEvidence(
		r.Context(), req.OrganisationID, req.AssessmentID, req.SchemaVersion,
		reportHashHex, req.Report, submittedBy, wormEntry.ID,
	)
	if err != nil {
		// The event is already durably recorded in the WORM chain (see
		// InsertComplianceEvidence's doc comment) even though this failed —
		// surface a real error so the caller knows the record is not yet
		// retrievable via GET and can retry, rather than reporting success
		// for a submission that isn't actually queryable yet.
		e.logger.Error().Err(err).Str("worm_entry_id", wormEntry.ID.String()).Msg("evidence submit: insert evidence row failed after WORM append succeeded")
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	e.logger.Info().
		Str("organisation_id", req.OrganisationID).
		Str("assessment_id", req.AssessmentID).
		Str("worm_entry_id", wormEntry.ID.String()).
		Str("evidence_id", entry.ID.String()).
		Msg("compliance evidence submitted")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(submitEvidenceResponse{
		ID:          entry.ID.String(),
		WORMEntryID: wormEntry.ID.String(),
		ChainHash:   wormEntry.ChainHash,
		SubmittedAt: entry.SubmittedAt,
	})
}

// Get handles GET /api/v1/evidence/{id} — returns a single evidence record.
// Public within CITADEL's existing trust model: like keys.Get, this read
// path carries no auth today (no caller-identity requirement is documented
// for reads elsewhere in this package); write is where RBAC is enforced.
func (e *Evidence) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "id must be a valid UUID")
		return
	}

	entry, exists, err := e.store.GetComplianceEvidence(r.Context(), id)
	if err != nil {
		e.logger.Error().Err(err).Str("id", idStr).Msg("evidence get: lookup failed")
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !exists {
		writeJSONError(w, http.StatusNotFound, "no compliance evidence found for id")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toEvidenceResponse(entry))
}

// listEvidenceResponse is the envelope for GET /api/v1/evidence.
type listEvidenceResponse struct {
	Data []evidenceResponse `json:"data"`
}

// List handles GET /api/v1/evidence?organisation_id=...&assessment_id=... —
// at least one filter is required (an unfiltered full-table scan is not a
// legitimate query for an audit-evidence store expected to grow unbounded).
func (e *Evidence) List(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("organisation_id")
	assessmentID := r.URL.Query().Get("assessment_id")
	if orgID == "" && assessmentID == "" {
		writeJSONError(w, http.StatusBadRequest, "organisation_id and/or assessment_id query parameter is required")
		return
	}

	entries, err := e.store.ListComplianceEvidence(r.Context(), orgID, assessmentID)
	if err != nil {
		e.logger.Error().Err(err).Msg("evidence list: query failed")
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	out := make([]evidenceResponse, 0, len(entries))
	for _, entry := range entries {
		out = append(out, toEvidenceResponse(entry))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(listEvidenceResponse{Data: out})
}
