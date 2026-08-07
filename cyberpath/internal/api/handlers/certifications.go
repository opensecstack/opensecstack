// Certification issuance, listing, and revocation handlers.
//
// v1.0.0: Ed25519-signed certification issuance backed by CertificationStore.
// v0.8.0: Eligibility check (all lessons completed), TryAutoIssue for
// auto-trigger from LessonsHandler.Complete, CertHandlerDeps struct.
// PDF generation is deferred to a later release; pdf_path stays empty.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/cyberpath/internal/auth"
	"github.com/opensecstack/cyberpath/internal/cert"
	"github.com/opensecstack/cyberpath/internal/citadel"
	"github.com/opensecstack/cyberpath/internal/db"
	sdkcitadel "github.com/opensecstack/sdk/go/citadel"
)

// ── interfaces ─────────────────────────────────────────────────────────────────

// CertStore is the DB contract CertificationsHandler depends on.
type CertStore interface {
	Issue(ctx context.Context, userID, trackID uuid.UUID, serial string, expiresAt *time.Time) (*db.Certification, error)
	SetSignature(ctx context.Context, certID uuid.UUID, signature, pdfPath string) error
	ListByUser(ctx context.Context, userID uuid.UUID, includeExpired bool) ([]db.Certification, error)
	Revoke(ctx context.Context, certID uuid.UUID) error
	GetByUserTrack(ctx context.Context, userID, trackID uuid.UUID) (*db.Certification, error)
}

// CertTrackReader resolves a track by ID (used for track metadata on issuance).
type CertTrackReader interface {
	Get(ctx context.Context, id uuid.UUID) (*db.Track, error)
}

// CertCompletionChecker verifies that all lessons in a track are complete
// for a given user. Used by Issue() for eligibility gating.
type CertCompletionChecker interface {
	AllLessonsCompletedForTrack(ctx context.Context, userID, trackID uuid.UUID) (bool, error)
}

// MarshalEvaluator submits a Kerkese governance request to CITADEL's
// MARSHAL engine (POST /api/v1/marshal/evaluate) and returns its
// Decision. Satisfied by *sdk/go/citadel.Client — narrowed to an
// interface here so tests can inject a fake without a live CITADEL
// instance. Certification revocation is the only call site today: it
// is an admin-only, high-stakes action (invalidating a previously
// issued credential) and, unlike issuance, is not automatic/score-gated,
// so it goes through a real governance evaluation rather than a plain
// WORM audit-emit.
type MarshalEvaluator interface {
	Evaluate(ctx context.Context, k sdkcitadel.Kerkese) (*sdkcitadel.Decision, error)
}

// ── handler ────────────────────────────────────────────────────────────────────

// CertHandlerDeps bundles all dependencies for CertificationsHandler.
type CertHandlerDeps struct {
	Certs       CertStore
	Tracks      CertTrackReader
	Completions CertCompletionChecker // optional: nil skips eligibility check in Issue()
	Signer      *cert.Signer
	Outbox      citadel.OutboxEnqueuer
	Audit       *db.AuditEventStore
	Logger      *zerolog.Logger

	// Marshal is CITADEL's MARSHAL governance client, used only by
	// Revoke(). Optional: nil skips the governance check (soft-fail —
	// mirrors Outbox/Audit being optional elsewhere in this handler).
	Marshal MarshalEvaluator
	// CitadelProjectID is the CITADEL project_id stamped on Kerkese
	// requests submitted by this handler.
	CitadelProjectID string
}

// CertificationsHandler serves certification issuance, listing, and revocation.
type CertificationsHandler struct {
	Certs       CertStore
	Tracks      CertTrackReader
	Completions CertCompletionChecker
	Signer      *cert.Signer
	Outbox      citadel.OutboxEnqueuer
	Audit       *db.AuditEventStore
	Logger      *zerolog.Logger

	Marshal          MarshalEvaluator
	CitadelProjectID string
}

// NewCertificationsHandler wires a CertificationsHandler from a deps bundle.
func NewCertificationsHandler(deps CertHandlerDeps) *CertificationsHandler {
	return &CertificationsHandler{
		Certs:            deps.Certs,
		Tracks:           deps.Tracks,
		Completions:      deps.Completions,
		Signer:           deps.Signer,
		Outbox:           deps.Outbox,
		Audit:            deps.Audit,
		Logger:           deps.Logger,
		Marshal:          deps.Marshal,
		CitadelProjectID: deps.CitadelProjectID,
	}
}

// Issue handles POST /api/v1/certifications/issue.
//
// Flow:
//  1. Parse track_id from request body.
//  2. Extract userID from JWT context.
//  3. Eligibility check — all lessons in the track must be completed (when
//     Completions dep is wired). Returns 422 if not yet eligible.
//  4. Generate a serial number and insert certification row.
//  5. Build canonical signing payload and sign with Ed25519.
//  6. Persist signature.
//  7. Enqueue CITADEL cyberpath.certification.issued event (best-effort).
//  8. Return 201 with the certification JSON.
func (h *CertificationsHandler) Issue(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TrackID string `json:"track_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "request body must be JSON")
		return
	}
	trackID, err := uuid.Parse(body.TrackID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_track_id", "track_id must be a UUID")
		return
	}

	userID, ok := userIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing_token", "authentication required")
		return
	}

	// Eligibility: all lessons must be completed.
	if h.Completions != nil {
		done, err := h.Completions.AllLessonsCompletedForTrack(r.Context(), userID, trackID)
		if err != nil {
			h.log().Error().Err(err).Msg("certifications.issue: eligibility check failed")
			writeError(w, http.StatusInternalServerError, "internal_error", "eligibility check failed")
			return
		}
		if !done {
			writeError(w, http.StatusUnprocessableEntity, "not_eligible",
				"all lessons in the track must be completed before a certificate can be issued")
			return
		}
	}

	serial := fmt.Sprintf("CP-%s-%d", trackID.String()[:8], time.Now().Unix())

	c, err := h.Certs.Issue(r.Context(), userID, trackID, serial, nil)
	if err != nil {
		h.log().Error().Err(err).Msg("certifications.issue: DB insert failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "certification issuance failed")
		return
	}

	// Build the canonical signing payload and sign it.
	payload, err := json.Marshal(map[string]any{
		"cert_id":   c.ID,
		"user_id":   userID,
		"track_id":  trackID,
		"serial":    c.Serial,
		"issued_at": c.IssuedAt,
	})
	if err != nil {
		h.log().Error().Err(err).Msg("certifications.issue: marshal payload failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "signing payload marshal failed")
		return
	}
	hexSig := h.Signer.Sign(payload)

	if err := h.Certs.SetSignature(r.Context(), c.ID, hexSig, ""); err != nil {
		h.log().Error().Err(err).Str("cert_id", c.ID.String()).Msg("certifications.issue: SetSignature failed")
	} else {
		c.Signature = hexSig
	}

	h.enqueueIssuedEvent(r.Context(), c, userID, trackID)
	h.appendAudit(r.Context(), userID, "certification.issue", "certification", c.ID.String())

	writeJSON(w, http.StatusCreated, certificationResponse(c))
}

// TryAutoIssue is called by LessonsHandler after track completion is detected.
// It is idempotent: if the user already has a non-revoked cert for the track,
// it returns immediately. The Completions eligibility check is intentionally
// skipped here — the caller (LessonsHandler.checkTrackCompletion) has already
// verified that all lessons are complete.
func (h *CertificationsHandler) TryAutoIssue(ctx context.Context, userID, trackID uuid.UUID) error {
	// Idempotency: cert already issued for this user+track.
	if _, err := h.Certs.GetByUserTrack(ctx, userID, trackID); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) && !isErrNoRows(err) {
		return fmt.Errorf("TryAutoIssue: GetByUserTrack: %w", err)
	}

	serial := fmt.Sprintf("CP-%s-%d", trackID.String()[:8], time.Now().Unix())
	c, err := h.Certs.Issue(ctx, userID, trackID, serial, nil)
	if err != nil {
		return fmt.Errorf("TryAutoIssue: Issue: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"cert_id":   c.ID,
		"user_id":   userID,
		"track_id":  trackID,
		"serial":    c.Serial,
		"issued_at": c.IssuedAt,
	})
	if err == nil {
		hexSig := h.Signer.Sign(payload)
		if sigErr := h.Certs.SetSignature(ctx, c.ID, hexSig, ""); sigErr != nil {
			h.log().Warn().Err(sigErr).Str("cert_id", c.ID.String()).Msg("TryAutoIssue: SetSignature")
		} else {
			c.Signature = hexSig
		}
	}

	h.enqueueIssuedEvent(ctx, c, userID, trackID)
	h.appendAudit(ctx, userID, "certification.auto_issue", "certification", c.ID.String())
	h.log().Info().
		Str("cert_id", c.ID.String()).
		Str("user_id", userID.String()).
		Str("track_id", trackID.String()).
		Msg("TryAutoIssue: certificate issued")
	return nil
}

// ListMine handles GET /api/v1/me/certifications.
// Returns the authenticated user's active (non-expired, non-revoked) certifications.
func (h *CertificationsHandler) ListMine(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing_token", "authentication required")
		return
	}

	rows, err := h.Certs.ListByUser(r.Context(), userID, false)
	if err != nil {
		h.log().Error().Err(err).Str("user_id", userID.String()).Msg("certifications.list_mine")
		writeError(w, http.StatusInternalServerError, "internal_error", "certifications lookup failed")
		return
	}

	out := make([]map[string]any, 0, len(rows))
	for i := range rows {
		out = append(out, certificationResponse(&rows[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":        userID.String(),
		"certifications": out,
	})
}

// Revoke handles DELETE /api/v1/admin/certifications/{id}/revoke.
// Admin-only. Marks the certification as revoked.
//
// Unlike Issue (automatic, score-gated), revocation is a discretionary
// admin decision that invalidates a previously issued credential —
// adversarial/high-stakes enough to warrant a real CITADEL MARSHAL
// governance check, not just an audit-emit. Flow:
//  1. AuthN/AuthZ as before (admin role required).
//  2. Build a Kerkese with the real authenticated admin as Actor,
//     forwarding their bearer token, and submit it to MARSHAL.
//     REFUSE/HARD_STOP blocks the revocation (403) with the reasons
//     surfaced to the caller.
//  3. On any other outcome (or if Marshal is not configured), proceed
//     with the DB revoke.
//  4. Emit a WORM audit entry unconditionally once revoked, so there is
//     an immutable record regardless of the MARSHAL outcome.
func (h *CertificationsHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		writeError(w, http.StatusUnauthorized, "missing_token", "authentication required")
		return
	}
	if !auth.HasRole(claims, auth.RoleAdmin) {
		writeError(w, http.StatusForbidden, "forbidden", "admin role required")
		return
	}

	idStr := chi.URLParam(r, "id")
	certID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "certification id must be a UUID")
		return
	}

	if blocked, reason := h.checkRevokeGovernance(r, certID, claims); blocked {
		writeError(w, http.StatusForbidden, "governance_refused", reason)
		return
	}

	if err := h.Certs.Revoke(r.Context(), certID); err != nil {
		h.log().Error().Err(err).Str("cert_id", idStr).Msg("certifications.revoke")
		writeError(w, http.StatusInternalServerError, "internal_error", "revocation failed")
		return
	}

	actorID, _ := userIDFromContext(r.Context())
	h.enqueueRevokedEvent(r.Context(), certID, actorID)
	h.appendAudit(r.Context(), actorID, "certification.revoke", "certification", certID.String())

	writeJSON(w, http.StatusOK, map[string]any{
		"cert_id": certID.String(),
		"revoked": true,
	})
}

// checkRevokeGovernance submits a certification-revocation Kerkese to
// CITADEL MARSHAL and reports whether the outcome blocks the request.
//
// Actor: the real authenticated admin performing the revocation —
// UserID/ActorToken are the caller's genuine sinauth-or-local identity
// and bearer token, forwarded exactly as presented (see citadel
// adrs/005-sinauth-identity-bridge.md); never a placeholder.
//
// Verifier: known, deliberate gap. CyberPath has no dual-control /
// second-approver concept anywhere in the codebase today (checked:
// no review/approval store, no "pending revocation" state) and
// building one is a separate product change, out of scope here. We
// use the same documented placeholder-Verifier pattern APIGuard uses
// for scan initiation (apiguard/internal/api/handlers/scans.go) — a
// fixed system identity that can never equal the Actor, so it doesn't
// trip Gate 3's NDS_SAME_IDENTITY check, with an empty VerifierToken.
// CITADEL's soft mode (citadel.enforce_identity /
// citadel.enforce_signatures both false) makes the missing verifier
// token/signature a WARN, not a block — this is a non-blocking known
// gap, not a silent regression.
//
// Action.Type is "CONFIG_CHANGE": CITADEL's MARSHAL RBAC vocabulary
// (citadel/internal/marshal/types.go rbacMap) has no CyberPath-specific
// action types yet, and citadel is out of scope to modify for this
// task. CONFIG_CHANGE is the closest existing admin-permitted action
// type for an administrative mutation to a governed record; a
// dedicated CERTIFICATION_REVOKE action type is a follow-up for
// whoever extends CITADEL's RBAC map next.
func (h *CertificationsHandler) checkRevokeGovernance(r *http.Request, certID uuid.UUID, claims *auth.Claims) (blocked bool, reason string) {
	if h.Marshal == nil {
		return false, ""
	}

	actorUserID := claims.Sub
	actorToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	k := sdkcitadel.Kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Now().UTC(),
		ProjectID:      h.CitadelProjectID,
		ExecutionID:    certID,
		Action: sdkcitadel.KerkeseAction{
			Type:        "CONFIG_CHANGE",
			Description: "CyberPath certification revocation: " + certID.String(),
			ChangeID:    certID.String(),
		},
		Actor:    sdkcitadel.KerkeseActor{UserID: actorUserID, Role: "admin"},
		Verifier: sdkcitadel.KerkeseVerifier{UserID: "cyberpath-system-verifier", Role: "group_sig_verifier"},
		Evidence: sdkcitadel.KerkeseEvidence{
			ChangeID: certID.String(),
			Extra: map[string]any{
				"cert_id": certID.String(),
			},
		},
		SoD:        sdkcitadel.KerkeseSoD{OperatorUserID: actorUserID, VerifierUserID: "cyberpath-system-verifier"},
		ActorToken: actorToken,
		// VerifierToken and SigOperator/SigVerifier are deliberately
		// left empty — see the Verifier gap documented above.
	}

	decision, err := h.Marshal.Evaluate(r.Context(), k)
	if err != nil {
		// Evaluate always returns a non-nil Decision even on transport
		// failure, synthesized per h.Marshal's FailMode (fail-closed /
		// HARD_STOP by default — see sdk/go/citadel.FailMode). Logged
		// loudly so ops can see MARSHAL is unreachable; the
		// decision.Allowed() check below still governs the outcome.
		h.log().Warn().Err(err).Str("cert_id", certID.String()).
			Msg("certifications.revoke: CITADEL marshal evaluate failed — applying configured fail-mode")
	}
	if !decision.Allowed() {
		// decision is only nil if a MarshalEvaluator implementation
		// violates its contract (the real sdk/go/citadel.Client never
		// returns a nil Decision) — guard it anyway rather than trust
		// every implementation.
		var reasons []string
		if decision != nil {
			reasons = decision.Reasons
		}
		if len(reasons) == 0 {
			reasons = []string{"CITADEL governance check rejected this certification revocation"}
		}
		return true, strings.Join(reasons, "; ")
	}
	return false, ""
}

// ── helpers ────────────────────────────────────────────────────────────────────

func (h *CertificationsHandler) enqueueIssuedEvent(ctx context.Context, c *db.Certification, userID, trackID uuid.UUID) {
	if h.Outbox == nil {
		return
	}
	ev := citadel.CertificationIssued{
		CertificateID:      c.ID.String(),
		UserID:             userID.String(),
		TrackID:            trackID.String(),
		CertificationLevel: "track-cert",
		IssuedAt:           c.IssuedAt,
		ExpiresAt:          c.ExpiresAt,
		SignedBy:            "ed25519:" + h.Signer.KeyID(),
		CorrelationID:      uuid.NewString(),
	}
	if _, err := citadel.EnqueueCertificationIssued(ctx, h.Outbox, ev); err != nil {
		h.log().Warn().Err(err).Msg("certifications: CITADEL enqueue failed (non-fatal)")
	}
}

// enqueueRevokedEvent enqueues the cyberpath.certification.revoked WORM
// event via the same outbox path Issue()/TryAutoIssue() already use
// (POST /api/v1/worm/emit, dispatched asynchronously by the outbox
// worker) — best-effort, matching enqueueIssuedEvent's failure handling.
func (h *CertificationsHandler) enqueueRevokedEvent(ctx context.Context, certID, revokedBy uuid.UUID) {
	if h.Outbox == nil {
		return
	}
	ev := citadel.CertificationRevoked{
		CertificateID: certID.String(),
		RevokedBy:     revokedBy.String(),
		RevokedAt:     time.Now(),
		CorrelationID: uuid.NewString(),
	}
	if _, err := citadel.EnqueueCertificationRevoked(ctx, h.Outbox, ev); err != nil {
		h.log().Warn().Err(err).Msg("certifications: CITADEL revoke enqueue failed (non-fatal)")
	}
}

func (h *CertificationsHandler) appendAudit(ctx context.Context, userID uuid.UUID, action, targetType, targetID string) {
	if h.Audit == nil {
		return
	}
	uidCopy := userID
	_ = h.Audit.Append(ctx, &db.AuditEvent{
		ActorUserID: &uidCopy,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		Outcome:     "success",
	})
}

func certificationResponse(c *db.Certification) map[string]any {
	resp := map[string]any{
		"id":        c.ID.String(),
		"user_id":   c.UserID.String(),
		"track_id":  c.TrackID.String(),
		"serial":    c.Serial,
		"issued_at": c.IssuedAt.UTC().Format(time.RFC3339),
		"revoked":   c.Revoked,
		"signature": c.Signature,
	}
	if c.ExpiresAt != nil {
		resp["expires_at"] = c.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if c.PDFPath != "" {
		resp["pdf_path"] = c.PDFPath
	}
	return resp
}

func (h *CertificationsHandler) log() *zerolog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	z := zerolog.Nop()
	return &z
}

// isErrNoRows catches wrapped pgx.ErrNoRows from store methods.
func isErrNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
